//! Blocking store failures are isolated and rendered through AppError's mapping.
mod common;

use axum::http::StatusCode;
use common::{Call, NYXMON_TOKEN, TestApp, ticket_payload};
use http_body_util::BodyExt;
use opsgate_web::error::error_response;
use opsgate_web::session::{SessionData, SessionHandle};

#[tokio::test]
async fn store_errors_and_panics_leave_the_application_usable() {
    let app = TestApp::new();
    let session = SessionHandle::new(SessionData::default());
    for panic_task in [false, true] {
        let failed = app
            .state
            .blocking(move |store| {
                if panic_task {
                    panic!("synthetic-private-panic-marker");
                }
                store.get_ticket("synthetic-missing-ticket")
            })
            .await
            .unwrap_err();
        let response = error_response("/api/v1/tickets/synthetic", &session, &failed);
        assert_eq!(
            response.status(),
            if panic_task {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::NOT_FOUND
            }
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("synthetic-private-panic-marker"));
        assert!(!text.contains("store task"));
        if !panic_task {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"],
                "ticket_not_found"
            );
        }
        // Exercise both the blocking bridge and the real router after failure.
        assert_eq!(
            app.state.blocking(|store| store.health()).await.unwrap()["status"],
            "ok"
        );
        let id = app
            .create_ticket(NYXMON_TOKEN, ticket_payload("Healthy after failure", None))
            .await;
        let response = app
            .send(
                Call::new(axum::http::Method::GET, &format!("/api/v1/tickets/{id}"))
                    .bearer(NYXMON_TOKEN),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK);
    }
}
