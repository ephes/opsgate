//! SQLite store of the OpsGate Rust port (`rust/PLAN.md` section 0): the
//! schema of 4.10 (same DDL text as `service.py:init_db`), the ticket
//! lifecycle of 4.7, health and `check-db`.
//!
//! Like Python, every operation opens its own connection (WAL, foreign keys,
//! 5 s busy timeout) and every mutation runs inside `BEGIN IMMEDIATE`; the
//! web layer calls these synchronous functions from `spawn_blocking` (6.1).
//! Operations return the ticket serialised as `_serialize_ticket` does
//! (4.6). Domain errors are [`StoreError::Service`]; every other error is a
//! 500.
//!
//! Slice S3a: [`Store::open`] (`init_db` with the session-state sync), the
//! session generation, ticket creation with lazy expiry and dedupe, get,
//! list, health, and [`check::check_db`]. Slice S3b adds the transitions,
//! claim and runner status.

pub mod audit;
pub mod check;
mod connection;
mod create;
mod error;
mod health;
pub mod schema;
mod session;
pub mod ticket;

use std::path::Path;

use opsgate_core::settings::{ApiSettings, SubmitterPolicy};
use opsgate_core::validate::{
    NewTicketContext, normalize_new_ticket, require_reviewer_step_floor_for_source,
};
use rusqlite::Connection;
use serde_json::{Map, Value};

pub use create::{Actor, maybe_expire_ticket};
pub use error::{StoreError, Unreadable};
pub use session::password_fingerprint;
pub use ticket::{ArchivedFilter, TicketRow};

/// A serialised ticket (`_serialize_ticket`, 4.6).
pub type Ticket = Map<String, Value>;

/// The store of one API process (`OpsGateService`): its settings and the
/// database at `settings.db_path`.
#[derive(Debug, Clone)]
pub struct Store {
    settings: ApiSettings,
}

impl Store {
    /// `OpsGateService(settings)`: create the database's parent directory
    /// (`mkdir -p`), then [`Store::init_db`].
    pub fn open(settings: ApiSettings) -> Result<Self, StoreError> {
        let store = Self { settings };
        if let Some(parent) = store.db_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        store.init_db()?;
        Ok(store)
    }

    /// The settings the store was opened with.
    pub fn settings(&self) -> &ApiSettings {
        &self.settings
    }

    /// `OPSGATE_DB_PATH`.
    pub fn db_path(&self) -> &Path {
        Path::new(&self.settings.db_path)
    }

    /// `_connection()`: a new connection with the pragmas of 4.7.
    pub fn connect(&self) -> Result<Connection, StoreError> {
        Ok(connection::connect(self.db_path())?)
    }

    /// `init_db`: the idempotent DDL of 4.10 ([`schema::apply`]), then the
    /// session-state sync for the configured approver (4.5.2).
    pub fn init_db(&self) -> Result<(), StoreError> {
        schema::apply(&self.connect()?)?;
        session::sync(
            &mut self.connect()?,
            &self.settings.ui_username,
            &self.settings.ui_password_bcrypt,
        )
    }

    /// `get_ui_session_generation`.
    pub fn ui_session_generation(&self, username: &str) -> Result<Option<i64>, StoreError> {
        session::generation(&self.connect()?, username)
    }

    /// `revoke_ui_sessions`: the new generation, or 400 `unknown_approver`.
    pub fn revoke_ui_sessions(&self, username: &str) -> Result<i64, StoreError> {
        session::revoke(&mut self.connect()?, username)
    }

    /// `create_ticket`: a ticket from a submitter's JSON object, created by
    /// and audited as `submit:<source>` (4.7.1).
    pub fn create_ticket(
        &self,
        payload: &Map<String, Value>,
        submitter: &SubmitterPolicy,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let context =
            create::submitter_context(submitter, self.settings.max_duration_seconds_default());
        let actor = format!("submit:{}", submitter.source);
        self.insert(payload, &context, &actor, source_ip, user_agent)
    }

    /// `create_manual_ticket`: a ticket from the UI form, source `operator`
    /// with the operator submitter's reviewer floor, created by and audited
    /// as `approver:<creator>`.
    pub fn create_manual_ticket(
        &self,
        payload: &Map<String, Value>,
        creator: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let context = NewTicketContext {
            source: "operator",
            require_reviewer_step_floor: require_reviewer_step_floor_for_source(
                &self.settings.submitter_policies,
                "operator",
            ),
            max_duration_seconds_default: self.settings.max_duration_seconds_default(),
        };
        let actor = format!("approver:{creator}");
        self.insert(payload, &context, &actor, source_ip, user_agent)
    }

    fn insert(
        &self,
        payload: &Map<String, Value>,
        context: &NewTicketContext<'_>,
        actor: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let ticket = normalize_new_ticket(payload, context)?;
        create::insert_ticket(
            &mut self.connect()?,
            &ticket,
            actor,
            &Actor {
                actor,
                source_ip,
                user_agent,
            },
        )
    }

    /// `get_ticket`: the ticket, or 404 `ticket_not_found`.
    pub fn get_ticket(&self, ticket_id: &str) -> Result<Ticket, StoreError> {
        ticket::select_ticket(&self.connect()?, ticket_id)?
            .ok_or_else(|| StoreError::from(ticket::ticket_not_found()))?
            .serialize()
    }

    /// `list_tickets(limit, archived=…)`: newest first by `created_at`.
    pub fn list_tickets(
        &self,
        limit: i64,
        archived: ArchivedFilter,
    ) -> Result<Vec<Ticket>, StoreError> {
        ticket::list_tickets(&self.connect()?, limit, archived)
    }

    /// `health()` (4.6).
    pub fn health(&self) -> Result<Map<String, Value>, StoreError> {
        health::health(&self.connect()?, &self.settings.service_name)
    }
}
