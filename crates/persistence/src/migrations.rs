use crate::db::Database;
use crate::PersistenceResult;

/// Run all pending migrations against the provided database.
pub fn apply_migrations(db: &Database) -> PersistenceResult<()> {
	db.run_migrations()
}
