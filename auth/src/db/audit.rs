// auth/src/db/audit.rs
use anyhow::Result;
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;
use crate::crypto;

pub struct AuditEntry {
    pub event_type: String,
    pub actor_id: Option<Uuid>,
    pub actor_username: Option<String>,
    pub actor_ip: Option<IpAddr>,
    pub actor_ua: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

pub async fn append(db: &PgPool, entry: AuditEntry) -> Result<()> {
    use sqlx::Row;

    let prev_hash: Option<String> = sqlx::query(
        "SELECT entry_hash FROM audit.log ORDER BY id DESC LIMIT 1"
    )
    .fetch_optional(db)
    .await?
    .map(|r| r.get("entry_hash"));

    let now = time::OffsetDateTime::now_utc();
    let timestamp = now.to_string();
    let actor = entry.actor_username.as_deref().unwrap_or("system");

    let entry_hash = crypto::audit_entry_hash(
        prev_hash.as_deref(),
        &entry.event_type,
        actor,
        &entry.action,
        &entry.outcome,
        &timestamp,
    );

    let actor_ip_str = entry.actor_ip.map(|ip| ip.to_string());

    sqlx::query(
        r#"INSERT INTO audit.log
           (prev_hash, entry_hash, event_type, actor_id, actor_username,
            actor_ip, actor_ua, target_type, target_id, action, outcome, reason, metadata)
           VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11, $12, $13)"#
    )
    .bind(&prev_hash)
    .bind(&entry_hash)
    .bind(&entry.event_type)
    .bind(entry.actor_id)
    .bind(&entry.actor_username)
    .bind(actor_ip_str.as_deref())
    .bind(&entry.actor_ua)
    .bind(&entry.target_type)
    .bind(&entry.target_id)
    .bind(&entry.action)
    .bind(&entry.outcome)
    .bind(&entry.reason)
    .bind(&entry.metadata)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn recent(db: &PgPool, limit: i64, offset: i64) -> Result<Vec<serde_json::Value>> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"SELECT entry_id, event_type, actor_username, actor_ip::text as actor_ip,
                  target_type, target_id, action, outcome, reason, metadata, created_at
           FROM audit.log ORDER BY id DESC LIMIT $1 OFFSET $2"#
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await?;

    Ok(rows.iter().map(|r| {
        let created_at: time::OffsetDateTime = r.get("created_at");
        serde_json::json!({
            "entry_id": r.get::<Uuid, _>("entry_id"),
            "event_type": r.get::<String, _>("event_type"),
            "actor": r.get::<Option<String>, _>("actor_username"),
            "actor_ip": r.get::<Option<String>, _>("actor_ip"),
            "target_type": r.get::<Option<String>, _>("target_type"),
            "target_id": r.get::<Option<String>, _>("target_id"),
            "action": r.get::<String, _>("action"),
            "outcome": r.get::<String, _>("outcome"),
            "reason": r.get::<Option<String>, _>("reason"),
            "metadata": r.get::<Option<serde_json::Value>, _>("metadata"),
            "created_at": created_at.to_string(),
        })
    }).collect())
}

pub async fn verify_chain(db: &PgPool) -> Result<(i64, Option<Uuid>)> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, entry_id, prev_hash, entry_hash, event_type, actor_username, action, outcome, created_at
         FROM audit.log ORDER BY id ASC"
    )
    .fetch_all(db)
    .await?;

    let total = rows.len() as i64;
    let mut prev_hash: Option<String> = None;

    for row in &rows {
        let event_type: String = row.get("event_type");
        let actor_username: Option<String> = row.get("actor_username");
        let action: String = row.get("action");
        let outcome: String = row.get("outcome");
        let created_at: time::OffsetDateTime = row.get("created_at");
        let entry_hash: String = row.get("entry_hash");

        let expected = crypto::audit_entry_hash(
            prev_hash.as_deref(),
            &event_type,
            actor_username.as_deref().unwrap_or("system"),
            &action,
            &outcome,
            &created_at.to_string(),
        );

        if expected != entry_hash {
            return Ok((total, Some(row.get("entry_id"))));
        }
        prev_hash = Some(entry_hash);
    }

    Ok((total, None))
}