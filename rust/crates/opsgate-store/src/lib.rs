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
//! list, health, and [`check::check_db`]. Slice S3b: the approver's
//! transitions (approve, reject, cancel, archive, unarchive), the runner's
//! claim and status update, and [`dump::dump_tickets`] (`check-db --dump`).

pub mod audit;
pub mod check;
mod claim;
mod connection;
mod create;
pub mod dump;
mod error;
mod health;
mod runner_status;
pub mod schema;
mod session;
pub mod ticket;
mod transitions;

use std::fmt;
use std::path::Path;

use opsgate_core::settings::{ApiSettings, SubmitterPolicy};
use opsgate_core::validate::{
    NewTicketContext, normalize_new_ticket, require_reviewer_step_floor_for_source,
};
use rusqlite::Connection;
use serde_json::{Map, Value};

pub use create::{Actor, maybe_expire_ticket};
pub use error::{StoreError, Unreadable};
pub use runner_status::RUNNER_EVENT_TYPES;
pub use session::password_fingerprint;
pub use ticket::{ArchivedFilter, TicketRow};
pub use transitions::{ReadHook, approval_checksum};

/// A serialised ticket (`_serialize_ticket`, 4.6).
pub type Ticket = Map<String, Value>;

/// The store of one API process (`OpsGateService`): its settings and the
/// database at `settings.db_path`.
#[derive(Clone)]
pub struct Store {
    settings: ApiSettings,
    read_hook: Option<ReadHook>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("db_path", &self.settings.db_path)
            .field("read_hook", &self.read_hook.is_some())
            .finish_non_exhaustive()
    }
}

/// `approver:<user>` with the request's address and user agent.
fn approver_actor<'a>(
    actor: &'a str,
    source_ip: Option<&'a str>,
    user_agent: Option<&'a str>,
) -> Actor<'a> {
    Actor {
        actor,
        source_ip,
        user_agent,
    }
}

impl Store {
    /// `OpsGateService(settings)`: create the database's parent directory
    /// (`mkdir -p`), then [`Store::init_db`].
    pub fn open(settings: ApiSettings) -> Result<Self, StoreError> {
        let store = Self {
            settings,
            read_hook: None,
        };
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

    /// This store with a [`ReadHook`]: a test seam of the race tests only
    /// (PLAN.md 7.1), never set by the server.
    #[doc(hidden)]
    pub fn with_read_hook(mut self, hook: ReadHook) -> Self {
        self.read_hook = Some(hook);
        self
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

    /// `approve_ticket` (4.7.2): `pending_approval` → `approved` with the
    /// payload checksum recomputed from the stored fields.
    pub fn approve_ticket(
        &self,
        ticket_id: &str,
        approver: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let actor = format!("approver:{approver}");
        transitions::approve(
            &mut self.connect()?,
            ticket_id,
            approver,
            &approver_actor(&actor, source_ip, user_agent),
            self.read_hook.as_ref(),
        )
    }

    /// `reject_ticket` (4.7.2). `reason` is the request's `reason`, already
    /// `str()`-ed and stripped by the web layer; empty stores
    /// `rejected_by_approver`.
    pub fn reject_ticket(
        &self,
        ticket_id: &str,
        approver: &str,
        reason: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let actor = format!("approver:{approver}");
        transitions::reject(
            &mut self.connect()?,
            ticket_id,
            reason,
            &approver_actor(&actor, source_ip, user_agent),
            self.read_hook.as_ref(),
        )
    }

    /// `cancel_ticket` (4.7.2); an empty `reason` stores
    /// `canceled_by_approver`.
    pub fn cancel_ticket(
        &self,
        ticket_id: &str,
        approver: &str,
        reason: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let actor = format!("approver:{approver}");
        transitions::cancel(
            &mut self.connect()?,
            ticket_id,
            reason,
            &approver_actor(&actor, source_ip, user_agent),
            self.read_hook.as_ref(),
        )
    }

    /// `archive_ticket` (4.7.2).
    pub fn archive_ticket(
        &self,
        ticket_id: &str,
        approver: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let actor = format!("approver:{approver}");
        transitions::archive(
            &mut self.connect()?,
            ticket_id,
            approver,
            &approver_actor(&actor, source_ip, user_agent),
            self.read_hook.as_ref(),
        )
    }

    /// `unarchive_ticket` (4.7.2).
    pub fn unarchive_ticket(
        &self,
        ticket_id: &str,
        approver: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let actor = format!("approver:{approver}");
        transitions::unarchive(
            &mut self.connect()?,
            ticket_id,
            &approver_actor(&actor, source_ip, user_agent),
            self.read_hook.as_ref(),
        )
    }

    /// `claim_ticket` (4.7.3): the ticket now `running` for `runner_host`,
    /// or `None`. `runner_host` is the one the web layer derived (body
    /// `runner_host` stripped, else the client address, else `"runner"`).
    pub fn claim_ticket(
        &self,
        runner_host: &str,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Option<Ticket>, StoreError> {
        let actor = format!("runner:{runner_host}");
        claim::claim(
            &mut self.connect()?,
            Path::new(&self.settings.disable_file_path),
            &Actor {
                actor: &actor,
                source_ip,
                user_agent,
            },
            runner_host,
        )
    }

    /// `update_runner_status` (4.7.4): `payload` is the request's JSON
    /// object.
    pub fn update_runner_status(
        &self,
        ticket_id: &str,
        runner_host: &str,
        payload: &Map<String, Value>,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Ticket, StoreError> {
        let actor = format!("runner:{runner_host}");
        runner_status::update_runner_status(
            &mut self.connect()?,
            ticket_id,
            runner_host,
            payload,
            &Actor {
                actor: &actor,
                source_ip,
                user_agent,
            },
            self.read_hook.as_ref(),
        )
    }
}
