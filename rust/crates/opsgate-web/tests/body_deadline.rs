//! Elapsed request-body deadline through the authenticated router.
mod common;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use common::{NYXMON_TOKEN, TestApp, ticket_payload};
use futures_core::Stream;
use opsgate_web::BODY_READ_TIMEOUT;
use tower::ServiceExt;

struct SlowBody {
    polls: Arc<AtomicUsize>,
    chunks: Arc<AtomicUsize>,
    // None never produces a frame; Some produces one byte per second forever.
    tick: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Stream for SlowBody {
    type Item = Result<Bytes, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let Some(tick) = self.tick.as_mut() else {
            return Poll::Pending;
        };
        if tick.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        tick.as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(1));
        self.chunks.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Bytes::from_static(b" "))))
    }
}

async fn post(app: &TestApp, path: &str, token: Option<&str>, body: Body) -> Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let mut request = request.body(body).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
    ));
    opsgate_web::app(app.state.clone())
        .oneshot(request)
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn pending_and_trickling_bodies_have_one_elapsed_deadline() {
    let app = TestApp::new();
    for trickle in [false, true] {
        let polls = Arc::new(AtomicUsize::new(0));
        let chunks = Arc::new(AtomicUsize::new(0));
        let body = SlowBody {
            polls: polls.clone(),
            chunks: chunks.clone(),
            tick: trickle.then(|| Box::pin(tokio::time::sleep(Duration::from_secs(1)))),
        };
        let before = app.snapshot();
        let started = tokio::time::Instant::now();
        let response = tokio::time::timeout(
            BODY_READ_TIMEOUT + Duration::from_secs(1),
            post(
                &app,
                "/api/v1/tickets",
                Some(NYXMON_TOKEN),
                Body::from_stream(body),
            ),
        )
        .await
        .expect("the handler must enforce its own body deadline");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(started.elapsed(), BODY_READ_TIMEOUT);
        assert!(polls.load(Ordering::SeqCst) > 0);
        if trickle {
            assert!(chunks.load(Ordering::SeqCst) > 1);
        }
        assert_eq!(app.snapshot(), before);
    }
}

#[tokio::test(start_paused = true)]
async fn unauthorized_pending_bodies_are_not_polled() {
    let app = TestApp::new();
    let before = app.snapshot();
    for path in [
        "/api/v1/tickets",
        "/api/v1/runner/claim",
        "/api/v1/runner/x/status",
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let body = SlowBody {
            polls: polls.clone(),
            chunks: Arc::new(AtomicUsize::new(0)),
            tick: None,
        };
        let started = tokio::time::Instant::now();
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            post(&app, path, None, Body::from_stream(body)),
        )
        .await
        .expect("auth must reject before body collection");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(app.snapshot(), before);
    }
}

#[tokio::test]
async fn ordinary_and_oversized_bodies_keep_their_statuses() {
    let app = TestApp::new();
    let before = app.snapshot();
    let response = post(
        &app,
        "/api/v1/tickets",
        Some(NYXMON_TOKEN),
        Body::from(vec![b' '; opsgate_web::BODY_LIMIT + 1]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(app.snapshot(), before);
    let response = post(
        &app,
        "/api/v1/tickets",
        Some(NYXMON_TOKEN),
        Body::from(ticket_payload("Ordinary body", None).to_string()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}
