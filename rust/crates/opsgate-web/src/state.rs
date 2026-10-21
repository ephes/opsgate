//! The application state: the store (with the API settings), the session
//! cookie key and the template environment.

use std::sync::Arc;

use cookie::Key;
use opsgate_core::settings::ApiSettings;
use opsgate_store::{Store, StoreError};

use crate::error::AppError;
use crate::session::session_key;
use crate::templates::Templates;

/// Shared by every request.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    store: Store,
    session_key: Key,
    templates: Templates,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("store", &self.0.store)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// The state of an API process around an opened store. Fails when an
    /// embedded template does not compile.
    pub fn new(store: Store) -> Result<Self, minijinja::Error> {
        let session_key = session_key(&store.settings().session_secret);
        Ok(Self(Arc::new(Inner {
            store,
            session_key,
            templates: Templates::new()?,
        })))
    }

    /// The store.
    pub fn store(&self) -> &Store {
        &self.0.store
    }

    /// The API settings (4.2).
    pub fn settings(&self) -> &ApiSettings {
        self.0.store.settings()
    }

    /// The session cookie key.
    pub fn session_key(&self) -> &Key {
        &self.0.session_key
    }

    /// The template environment.
    pub fn templates(&self) -> &Templates {
        &self.0.templates
    }

    /// Runs a store operation on the blocking pool (SQLite, PLAN.md 6.1).
    pub async fn blocking<T, F>(&self, operation: F) -> Result<T, AppError>
    where
        T: Send + 'static,
        F: FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
    {
        let state = self.clone();
        match tokio::task::spawn_blocking(move || operation(state.store())).await {
            Ok(result) => result.map_err(AppError::from),
            Err(error) => Err(AppError::Internal(format!("store task: {error}"))),
        }
    }
}
