use crate::db::SqlitePool;
use crate::models::MessageModel;
use rubix_domain::{Message, DomainResult, MessageState, DomainError, MessageError, Fingerprint};
use async_trait::async_trait;

pub trait MessageRepository: Send + Sync {
	async fn insert(&self, msg: &Message) -> DomainResult<()>;
	async fn get(&self, id: &uuid::Uuid) -> DomainResult<Message>;
	async fn update_state(&self, id: &uuid::Uuid, new_state: &MessageState) -> DomainResult<()>;
	async fn list_for_recipient(&self, fingerprint: &Fingerprint) -> DomainResult<Vec<Message>>;
	async fn delete(&self, id: &uuid::Uuid) -> DomainResult<()>;
}

pub struct SqliteMessageRepository {
	pool: SqlitePool,
}

impl SqliteMessageRepository {
	pub fn new(pool: SqlitePool) -> Self {
		Self { pool }
	}

	fn map_sql_error(e: rusqlite::Error) -> DomainError {
		match e {
			rusqlite::Error::QueryReturnedNoRows => DomainError::Message(MessageError::NotFound),
			_ => DomainError::Internal,
		}
	}
}

#[async_trait]
impl MessageRepository for SqliteMessageRepository {
	async fn insert(&self, msg: &Message) -> DomainResult<()> {
		let pool = self.pool.clone();
		let model = MessageModel::from(msg);

		let res = tokio::task::spawn_blocking(move || -> DomainResult<()> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;

			let tx = conn.transaction().map_err(|e| SqliteMessageRepository::map_sql_error(e))?;

			tx.execute(
				"INSERT INTO messages (id, sender_fingerprint, recipient_fingerprints, content, content_type, state, message_json, created_at, sent_at, delivered_at, read_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
				rusqlite::params![
					model.id,
					model.sender_fingerprint,
					model.recipient_fingerprints,
					model.content,
					model.content_type,
					model.state,
					model.message_json,
					model.created_at,
					model.sent_at,
					model.delivered_at,
					model.read_at,
				],
			).map_err(|e| SqliteMessageRepository::map_sql_error(e))?;

			// also insert into message_recipients normalized table if present
			if let Some(recipients) = model.recipient_fingerprints.as_ref() {
				for fp in recipients.split(',') {
					// recipient_fingerprints stored as CSV in model for now; keep behavior
					let _ = tx.execute("INSERT INTO message_recipients (message_id, recipient_fingerprint) VALUES (?1,?2)", rusqlite::params![model.id, fp]);
				}
			}

			tx.commit().map_err(|e| SqliteMessageRepository::map_sql_error(e))?;
			Ok(())
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn get(&self, id: &uuid::Uuid) -> DomainResult<Message> {
		let pool = self.pool.clone();
		let id_str = id.to_string();

		let res = tokio::task::spawn_blocking(move || -> DomainResult<Message> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let mut stmt = conn.prepare_cached("SELECT message_json FROM messages WHERE id = ?1").map_err(|e| SqliteMessageRepository::map_sql_error(e))?;

			let row = stmt.query_row(rusqlite::params![id_str], |r| r.get::<_, String>(0));
			match row {
				Ok(json) => {
					let msg: Message = serde_json::from_str(&json).map_err(|_| DomainError::Internal)?;
					Ok(msg)
				}
				Err(e) => Err(SqliteMessageRepository::map_sql_error(e)),
			}
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn update_state(&self, id: &uuid::Uuid, new_state: &MessageState) -> DomainResult<()> {
		let pool = self.pool.clone();
		let id_str = id.to_string();
		let state_json = serde_json::to_string(new_state).map_err(|_| DomainError::Internal)?;

		let res = tokio::task::spawn_blocking(move || -> DomainResult<()> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let rows = conn.execute("UPDATE messages SET state = ?1 WHERE id = ?2", rusqlite::params![state_json, id_str]).map_err(|e| SqliteMessageRepository::map_sql_error(e))?;
			if rows == 0 { return Err(DomainError::Message(MessageError::NotFound)); }
			Ok(())
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn list_for_recipient(&self, fingerprint: &Fingerprint) -> DomainResult<Vec<Message>> {
		let pool = self.pool.clone();
		let fp_str = fingerprint.to_string();

		let res = tokio::task::spawn_blocking(move || -> DomainResult<Vec<Message>> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;

			// Use normalized message_recipients table when available
			let mut stmt = conn.prepare_cached(
				"SELECT m.message_json FROM messages m JOIN message_recipients r ON m.id = r.message_id WHERE r.recipient_fingerprint = ?1 ORDER BY m.created_at DESC"
			).map_err(|e| SqliteMessageRepository::map_sql_error(e))?;

			let rows = stmt.query_map(rusqlite::params![fp_str], |r| r.get::<_, String>(0)).map_err(|e| SqliteMessageRepository::map_sql_error(e))?;

			let mut messages = Vec::new();
			for res in rows {
				match res {
					Ok(json) => {
						let msg: Message = match serde_json::from_str(&json) {
							Ok(m) => m,
							Err(_) => return Err(DomainError::Internal),
						};
						messages.push(msg);
					}
					Err(_) => return Err(DomainError::Internal),
				}
			}

			Ok(messages)
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn delete(&self, id: &uuid::Uuid) -> DomainResult<()> {
		let pool = self.pool.clone();
		let id_str = id.to_string();

		let res = tokio::task::spawn_blocking(move || -> DomainResult<()> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let rows = conn.execute("DELETE FROM messages WHERE id = ?1", rusqlite::params![id_str]).map_err(|e| SqliteMessageRepository::map_sql_error(e))?;
			if rows == 0 { return Err(DomainError::Message(MessageError::NotFound)); }
			// remove recipients too
			let _ = conn.execute("DELETE FROM message_recipients WHERE message_id = ?1", rusqlite::params![id_str]);
			Ok(())
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}
}

