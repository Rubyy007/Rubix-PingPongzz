use crate::error::{PersistenceError, PersistenceResult};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use rusqlite::params;
use tracing::{info, warn};
use std::path::Path;
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Connection pool type alias for SQLite connections.
pub type SqlitePool = Pool<SqliteConnectionManager>;

/// Database handle wrapping an r2d2 pool.
#[derive(Clone)]
pub struct Database {
	pool: SqlitePool,
}

		// Apply external SQL files in migrations/ directory (ordered by filename)
		// This allows adding standalone .sql files for later migrations.
		if let Ok(entries) = std::fs::read_dir("./crates/persistence/migrations") {
			let mut files: Vec<_> = entries.filter_map(|e| e.ok()).collect();
			files.sort_by_key(|f| f.file_name());
			for file in files {
				if let Some(name) = file.path().file_name().and_then(|n| n.to_str()) {
					if name.ends_with(".sql") {
						let id = name.to_string();
						let exists: Result<i64, rusqlite::Error> = tx.query_row(
							"SELECT 1 FROM schema_migrations WHERE id = ?1",
							params![id],
							|_r| Ok(1_i64),
						);
						if let Err(rusqlite::Error::QueryReturnedNoRows) = exists {
							if let Ok(sql) = std::fs::read_to_string(file.path()) {
								tx.execute_batch(&sql)?;
								let now = chrono::Utc::now().timestamp();
								tx.execute(
									"INSERT INTO schema_migrations (id, applied_at) VALUES (?1, ?2)",
									params![id, now],
								)?;
								info!("applied migration file {}", name);
							}
						}
					}
				}
			}
		}

impl Database {
	/// Create a new connection pool for the given SQLite file path.
	/// Use `:memory:` for an in-memory database.
	pub fn new(path: &str) -> Result<Self, PersistenceError> {
		// Ensure parent directory exists for file-based DBs
		if path != ":memory:" {
			if let Some(parent) = Path::new(path).parent() {
				if !parent.exists() {
					if let Err(e) = std::fs::create_dir_all(parent) {
						warn!("failed to create db parent dir {:?}: {}", parent, e);
					}
				}
			}

			// Ensure the file exists with safe permissions when possible
			if !Path::new(path).exists() {
				let mut opts = OpenOptions::new();
				opts.write(true).create(true);
				#[cfg(unix)]
				{
					// rw------- (0o600)
					opts.mode(0o600);
				}
				// best-effort create
				let _ = opts.open(path);
			}
		}

		let manager = SqliteConnectionManager::file(path);
		let pool = Pool::builder().build(manager)?;

		let db = Self { pool };

		// Configure pragmas on a pooled connection for better concurrency and durability
		let conn = db.pool.get()?;
		// Use WAL for better concurrency, enable foreign_keys and set busy timeout
		conn.execute_batch(
			"PRAGMA journal_mode = WAL;\nPRAGMA synchronous = NORMAL;\nPRAGMA foreign_keys = ON;\nPRAGMA busy_timeout = 5000;",
		)?;

		Ok(db)
	}

	/// Return a pool reference for use by repositories.
	pub fn pool(&self) -> &SqlitePool {
		&self.pool
	}

	/// Run initial migrations (idempotent).
	pub fn run_migrations(&self) -> PersistenceResult<()> {
		// Versioned migrations
		let migrations: Vec<(&str, &str)> = vec![
			(
				"001_create_core_tables",
				r#"
				CREATE TABLE IF NOT EXISTS schema_migrations (
					id TEXT PRIMARY KEY,
					applied_at INTEGER NOT NULL
				);

				CREATE TABLE IF NOT EXISTS peers (
					id TEXT PRIMARY KEY,
					display_name TEXT NOT NULL,
					fingerprint TEXT NOT NULL UNIQUE,
					ed25519_public BLOB NOT NULL,
					x25519_public BLOB NOT NULL,
					addresses TEXT NOT NULL,
					status TEXT NOT NULL,
					verified INTEGER NOT NULL DEFAULT 0,
					first_seen INTEGER NOT NULL,
					last_seen INTEGER NOT NULL
				);

				CREATE INDEX IF NOT EXISTS idx_peers_fingerprint ON peers(fingerprint);

				CREATE TABLE IF NOT EXISTS messages (
					id TEXT PRIMARY KEY,
					sender_fingerprint TEXT NOT NULL,
					recipient_fingerprints TEXT NOT NULL,
					content BLOB NOT NULL,
					content_type TEXT NOT NULL,
					state TEXT NOT NULL,
					message_json TEXT NOT NULL,
					created_at INTEGER NOT NULL,
					sent_at INTEGER,
					delivered_at INTEGER,
					read_at INTEGER
				);

				CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_fingerprint);
				CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);

				CREATE TABLE IF NOT EXISTS message_recipients (
					message_id TEXT NOT NULL,
					recipient_fingerprint TEXT NOT NULL,
					PRIMARY KEY (message_id, recipient_fingerprint)
				);

				CREATE INDEX IF NOT EXISTS idx_message_recipients_recipient ON message_recipients(recipient_fingerprint);
				"#,
			),
		];

		let mut conn = self.pool.get()?;
		// run migrations inside a transaction
		let tx = conn.transaction()?;

		// Ensure schema_migrations exists (creation part of first migration above too)
		tx.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);")?;

		for (id, sql) in migrations {
			// Check if applied
			let exists: Result<i64, rusqlite::Error> = tx.query_row(
				"SELECT 1 FROM schema_migrations WHERE id = ?1",
				params![id],
				|_r| Ok(1_i64),
			);

			if let Err(rusqlite::Error::QueryReturnedNoRows) = exists {
				// Apply migration
				tx.execute_batch(sql)?;
				// Record migration
				let now = chrono::Utc::now().timestamp();
				tx.execute(
					"INSERT INTO schema_migrations (id, applied_at) VALUES (?1, ?2)",
					params![id, now],
				)?;
				info!("applied migration {}", id);
			}
		}

		tx.commit()?;
		info!("persistence: migrations applied");
		Ok(())
	}
}

impl Database {
	/// Helper to create an in-memory database for tests.
	pub fn in_memory() -> Result<Self, PersistenceError> {
		Self::new(":memory:")
	}
}
