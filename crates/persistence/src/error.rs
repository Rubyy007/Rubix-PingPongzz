use thiserror::Error;

/// Errors produced by persistence layer operations.
#[derive(Error, Debug)]
pub enum PersistenceError {
	/// Generic rusqlite error.
	#[error("database error: {0}")]
	Sql(#[from] rusqlite::Error),

	/// Connection pool error from r2d2.
	#[error("connection pool error: {0}")]
	Pool(#[from] r2d2::Error),

	/// Serialization / deserialization error for JSON fields.
	#[error("serialization error: {0}")]
	Serialization(#[from] serde_json::Error),

	/// Not found (query returned no rows).
	#[error("not found")]
	NotFound,

	/// Unique constraint violation with an optional field/context.
	#[error("unique constraint violated: {0}")]
	UniqueViolation(String),

	/// Concurrent modification detected (optimistic concurrency failure).
	#[error("concurrent modification")]
	ConcurrentModification,

	/// Internal error with message.
	#[error("internal: {0}")]
	Internal(String),
}

/// Convenience result type for persistence operations.
pub type PersistenceResult<T> = Result<T, PersistenceError>;

impl From<rusqlite::Error> for PersistenceError {
	fn from(e: rusqlite::Error) -> Self {
		// Map common rusqlite error kinds to semantic persistence errors where possible.
		match e {
			rusqlite::Error::QueryReturnedNoRows => PersistenceError::NotFound,
			other => PersistenceError::Sql(other),
		}
	}
}
