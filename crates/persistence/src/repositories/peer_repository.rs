use crate::db::SqlitePool;
use crate::models::PeerModel;
use rubix_domain::{Peer, DomainResult, PeerError, DomainError, Fingerprint};
use async_trait::async_trait;
use tokio::task;

/// Repository trait for peers.
#[async_trait]
pub trait PeerRepository: Send + Sync {
	async fn insert(&self, peer: &Peer) -> DomainResult<()>;
	async fn get_by_fingerprint(&self, fp: &Fingerprint) -> DomainResult<Peer>;
	async fn update(&self, peer: &Peer) -> DomainResult<()>;
	async fn delete(&self, id: &uuid::Uuid) -> DomainResult<()>;
	async fn list_all(&self) -> DomainResult<Vec<Peer>>;
}

#[async_trait]
impl rubix_domain::TrustStore for SqlitePeerRepository {
	async fn is_trusted(&self, fp: &Fingerprint) -> DomainResult<bool> {
		let pool = self.pool.clone();
		let fp_str = fp.to_string();

		let res = task::spawn_blocking(move || -> Result<bool, rusqlite::Error> {
			let conn = pool.get()?;
			let mut stmt = conn.prepare_cached("SELECT trusted FROM peers WHERE fingerprint = ?1")?;
			let val: i64 = stmt.query_row(rusqlite::params![fp_str], |r| r.get(0))?;
			Ok(val == 1)
		})
		.await
		.map_err(|_| DomainError::Internal)?;

		match res {
			Ok(b) => Ok(b),
			Err(e) => Err(SqlitePeerRepository::map_sql_error(e)),
		}
	}

	async fn add_trusted(&self, fp: &Fingerprint) -> DomainResult<()> {
		let pool = self.pool.clone();
		let fp_str = fp.to_string();

		let res = task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
			let conn = pool.get()?;
			let rows = conn.execute("UPDATE peers SET trusted = 1 WHERE fingerprint = ?1", rusqlite::params![fp_str])?;
			if rows == 0 {
				// Insert minimal peer record with trusted flag if missing
				conn.execute(
					"INSERT OR IGNORE INTO peers (id, display_name, fingerprint, ed25519_public, x25519_public, addresses, status, verified, first_seen, last_seen, trusted) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1)",
					rusqlite::params![
						uuid::Uuid::new_v4().to_string(),
						"".to_string(),
						fp_str,
						vec![] as Vec<u8>,
						vec![] as Vec<u8>,
						"".to_string(),
						"unknown".to_string(),
						0i32,
						chrono::Utc::now().timestamp(),
						chrono::Utc::now().timestamp(),
					],
				)?;
			}
			Ok(())
		})
		.await
		.map_err(|_| DomainError::Internal)?;

		match res {
			Ok(_) => Ok(()),
			Err(e) => Err(SqlitePeerRepository::map_sql_error(e)),
		}
	}

	async fn list_trusted(&self) -> DomainResult<Vec<Fingerprint>> {
		let pool = self.pool.clone();

		let res = task::spawn_blocking(move || -> Result<Vec<Fingerprint>, rusqlite::Error> {
			let conn = pool.get()?;
			let mut stmt = conn.prepare_cached("SELECT fingerprint FROM peers WHERE trusted = 1")?;
			let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
			let mut out = Vec::new();
			for r in rows {
				let s: String = r?;
				let fp = Fingerprint::from_hex(&s).map_err(|_| rusqlite::Error::InvalidQuery)?;
				out.push(fp);
			}
			Ok(out)
		})
		.await
		.map_err(|_| DomainError::Internal)?;

		match res {
			Ok(v) => Ok(v),
			Err(e) => Err(SqlitePeerRepository::map_sql_error(e)),
		}
	}

	async fn add_peer(&self, peer: super::Peer) -> DomainResult<()> {
		// Reuse existing insert logic
		self.insert(&peer).await
	}

	async fn get_peer(&self, fp: &Fingerprint) -> DomainResult<Option<super::Peer>> {
		match self.get_by_fingerprint(fp).await {
			Ok(p) => Ok(Some(p)),
			Err(DomainError::Peer(PeerError::NotFound)) => Ok(None),
			Err(e) => Err(e),
		}
	}
}

/// SQLite implementation of PeerRepository.
pub struct SqlitePeerRepository {
	pool: SqlitePool,
}

impl SqlitePeerRepository {
	pub fn new(pool: SqlitePool) -> Self {
		Self { pool }
	}

	fn map_sql_error(e: rusqlite::Error) -> DomainError {
		match e {
			rusqlite::Error::QueryReturnedNoRows => DomainError::Peer(PeerError::NotFound),
			rusqlite::Error::SqliteFailure(_err, msg_opt) => {
				if let Some(msg) = msg_opt {
					if msg.contains("UNIQUE constraint failed") {
						return DomainError::Peer(PeerError::AlreadyExists);
					}
				}
				DomainError::Internal
			}
			_ => DomainError::Internal,
		}
	}
}

#[async_trait]
impl PeerRepository for SqlitePeerRepository {
	async fn insert(&self, peer: &Peer) -> DomainResult<()> {
		let pool = self.pool.clone();
		let model = PeerModel::from(peer);

		let res = task::spawn_blocking(move || -> DomainResult<()> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let tx = conn.transaction().map_err(|e| SqlitePeerRepository::map_sql_error(e))?;

			tx.execute(
				"INSERT INTO peers (id, display_name, fingerprint, ed25519_public, x25519_public, addresses, status, verified, first_seen, last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
				rusqlite::params![
					model.id,
					model.display_name,
					model.fingerprint,
					model.ed25519_public,
					model.x25519_public,
					model.addresses,
					model.status,
					model.verified,
					model.first_seen,
					model.last_seen
				],
			).map_err(|e| SqlitePeerRepository::map_sql_error(e))?;

			tx.commit().map_err(|e| SqlitePeerRepository::map_sql_error(e))?;
			Ok(())
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn get_by_fingerprint(&self, fp: &Fingerprint) -> DomainResult<Peer> {
		let pool = self.pool.clone();
		let fp_str = fp.to_string();

		let res = task::spawn_blocking(move || -> DomainResult<Peer> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let mut stmt = conn.prepare_cached("SELECT id, display_name, fingerprint, ed25519_public, x25519_public, addresses, status, verified, first_seen, last_seen FROM peers WHERE fingerprint = ?1").map_err(|e| SqlitePeerRepository::map_sql_error(e))?;

			let row = stmt.query_row(rusqlite::params![fp_str], |r| {
				Ok(PeerModel {
					id: r.get(0)?,
					display_name: r.get(1)?,
					fingerprint: r.get(2)?,
					ed25519_public: r.get(3)?,
					x25519_public: r.get(4)?,
					addresses: r.get(5)?,
					status: r.get(6)?,
					verified: r.get(7)?,
					first_seen: r.get(8)?,
					last_seen: r.get(9)?,
				})
			});

			match row {
				Ok(model) => match Peer::try_from(model) {
					Ok(peer) => Ok(peer),
					Err(_) => Err(DomainError::Internal),
				},
				Err(e) => Err(SqlitePeerRepository::map_sql_error(e)),
			}
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn update(&self, peer: &Peer) -> DomainResult<()> {
		let pool = self.pool.clone();
		let model = PeerModel::from(peer);

		let res = task::spawn_blocking(move || -> DomainResult<()> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let rows = conn.execute(
				"UPDATE peers SET display_name = ?1, ed25519_public = ?2, x25519_public = ?3, addresses = ?4, status = ?5, verified = ?6, last_seen = ?7 WHERE fingerprint = ?8",
				rusqlite::params![
					model.display_name,
					model.ed25519_public,
					model.x25519_public,
					model.addresses,
					model.status,
					model.verified,
					model.last_seen,
					model.fingerprint,
				],
			).map_err(|e| SqlitePeerRepository::map_sql_error(e))?;

			if rows == 0 {
				return Err(DomainError::Peer(PeerError::NotFound));
			}
			Ok(())
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn delete(&self, id: &uuid::Uuid) -> DomainResult<()> {
		let pool = self.pool.clone();
		let id_str = id.to_string();

		let res = task::spawn_blocking(move || -> DomainResult<()> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let rows = conn.execute("DELETE FROM peers WHERE id = ?1", rusqlite::params![id_str]).map_err(|e| SqlitePeerRepository::map_sql_error(e))?;
			if rows == 0 {
				return Err(DomainError::Peer(PeerError::NotFound));
			}
			Ok(())
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}

	async fn list_all(&self) -> DomainResult<Vec<Peer>> {
		let pool = self.pool.clone();

		let res = task::spawn_blocking(move || -> DomainResult<Vec<Peer>> {
			let conn = pool.get().map_err(|_| DomainError::Internal)?;
			let mut stmt = conn.prepare_cached("SELECT id, display_name, fingerprint, ed25519_public, x25519_public, addresses, status, verified, first_seen, last_seen FROM peers").map_err(|e| SqlitePeerRepository::map_sql_error(e))?;

			let models = stmt.query_map([], |r| {
				Ok(PeerModel {
					id: r.get(0)?,
					display_name: r.get(1)?,
					fingerprint: r.get(2)?,
					ed25519_public: r.get(3)?,
					x25519_public: r.get(4)?,
					addresses: r.get(5)?,
					status: r.get(6)?,
					verified: r.get(7)?,
					first_seen: r.get(8)?,
					last_seen: r.get(9)?,
				})
			}).map_err(|e| SqlitePeerRepository::map_sql_error(e))?;

			let mut peers = Vec::new();
			for m in models {
				match m {
					Ok(pm) => match Peer::try_from(pm) {
						Ok(p) => peers.push(p),
						Err(_) => return Err(DomainError::Internal),
					},
					Err(_) => return Err(DomainError::Internal),
				}
			}

			Ok(peers)
		}).await.map_err(|_| DomainError::Internal)??;

		Ok(res)
	}
}
