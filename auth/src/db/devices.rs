// auth/src/db/devices.rs
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub fingerprint: String,
    pub name: Option<String>,
    pub approved_at: Option<time::OffsetDateTime>,
    pub approved_by: Option<Uuid>,
    pub created_at: time::OffsetDateTime,
    pub last_seen: Option<time::OffsetDateTime>,
}

pub async fn is_approved(db: &PgPool, user_id: Uuid, fingerprint: &str) -> Result<bool> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE user_id = $1 AND fingerprint = $2 AND approved_at IS NOT NULL)"
    )
    .bind(user_id)
    .bind(fingerprint)
    .fetch_one(db)
    .await?;
    Ok(row.get::<bool, _>(0))
}

pub async fn register(db: &PgPool, user_id: Uuid, fingerprint: &str) -> Result<Uuid> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"INSERT INTO devices (user_id, fingerprint)
           VALUES ($1, $2)
           ON CONFLICT (user_id, fingerprint) DO UPDATE SET last_seen = NOW()
           RETURNING id"#
    )
    .bind(user_id)
    .bind(fingerprint)
    .fetch_one(db)
    .await?;
    Ok(row.get("id"))
}

pub async fn approve(db: &PgPool, device_id: Uuid, approved_by: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE devices SET approved_at = NOW(), approved_by = $1 WHERE id = $2"
    )
    .bind(approved_by)
    .bind(device_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_for_user(db: &PgPool, user_id: Uuid) -> Result<Vec<Device>> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, user_id, fingerprint, name, approved_at, approved_by, created_at, last_seen
         FROM devices WHERE user_id = $1 ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    Ok(rows.iter().map(|r| Device {
        id: r.get("id"),
        user_id: r.get("user_id"),
        fingerprint: r.get("fingerprint"),
        name: r.get("name"),
        approved_at: r.get("approved_at"),
        approved_by: r.get("approved_by"),
        created_at: r.get("created_at"),
        last_seen: r.get("last_seen"),
    }).collect())
}

pub async fn touch(db: &PgPool, user_id: Uuid, fingerprint: &str) -> Result<()> {
    sqlx::query(
        "UPDATE devices SET last_seen = NOW() WHERE user_id = $1 AND fingerprint = $2"
    )
    .bind(user_id)
    .bind(fingerprint)
    .execute(db)
    .await?;
    Ok(())
}