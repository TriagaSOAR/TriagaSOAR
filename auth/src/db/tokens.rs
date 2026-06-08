// auth/src/db/tokens.rs
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;
use crate::crypto;

#[derive(Debug)]
pub struct ActionToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub action_type: String,
    pub target: String,
    pub reason: String,
    pub session_id: Uuid,
}

pub async fn issue(
    db: &PgPool,
    user_id: Uuid,
    session_id: Uuid,
    action_type: &str,
    target: &str,
    reason: &str,
) -> Result<String> {
    if reason.len() < 20 {
        anyhow::bail!("Reason must be at least 20 characters");
    }

    let token = crypto::generate_token_hex();
    let token_hash = crypto::hash_token(&token)
        .map_err(|e| anyhow::anyhow!("Token hashing failed: {}", e))?;

    sqlx::query(
        "INSERT INTO action_tokens (user_id, session_id, token_hash, action_type, target, reason)
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(user_id)
    .bind(session_id)
    .bind(&token_hash)
    .bind(action_type)
    .bind(target)
    .bind(reason)
    .execute(db)
    .await?;

    Ok(token)
}

pub async fn consume(
    db: &PgPool,
    token: &str,
    action_type: &str,
    target: &str,
) -> Result<Option<ActionToken>> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, user_id, token_hash, action_type, target, reason, session_id
         FROM action_tokens
         WHERE consumed_at IS NULL AND expires_at > NOW()
           AND action_type = $1 AND target = $2"
    )
    .bind(action_type)
    .bind(target)
    .fetch_all(db)
    .await?;

    for row in rows {
        let token_hash: String = row.get("token_hash");
        if !crypto::verify_token(token, &token_hash) {
            continue;
        }
        let id: Uuid = row.get("id");
        sqlx::query("UPDATE action_tokens SET consumed_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(db)
            .await?;
        return Ok(Some(ActionToken {
            id,
            user_id: row.get("user_id"),
            action_type: row.get("action_type"),
            target: row.get("target"),
            reason: row.get("reason"),
            session_id: row.get("session_id"),
        }));
    }

    Ok(None)
}