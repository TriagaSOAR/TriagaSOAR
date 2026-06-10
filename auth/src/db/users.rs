// auth/src/db/users.rs
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;
use crate::{Config, crypto};

#[derive(Debug)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub totp_secret: Option<String>,
    pub totp_enrolled: bool,
    pub role: String,
    pub active: bool,
    pub failed_attempts: i32,
    pub lockout_until: Option<time::OffsetDateTime>,
}

pub async fn find_by_username(db: &PgPool, username: &str) -> Result<Option<User>> {
    let row = sqlx::query(
        "SELECT id, username, email, password_hash, totp_secret, totp_enrolled, role, active, failed_attempts, lockout_until
         FROM users WHERE username = $1 AND active = true"
    )
    .bind(username)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|r| {
        use sqlx::Row;
        User {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            totp_secret: r.get("totp_secret"),
            totp_enrolled: r.get("totp_enrolled"),
            role: r.get("role"),
            active: r.get("active"),
            failed_attempts: r.get("failed_attempts"),
            lockout_until: r.get("lockout_until"),
        }
    }))
}

pub async fn find_by_id(db: &PgPool, id: Uuid) -> Result<Option<User>> {
    let row = sqlx::query(
        "SELECT id, username, email, password_hash, totp_secret, totp_enrolled, role, active, failed_attempts, lockout_until
         FROM users WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|r| {
        use sqlx::Row;
        User {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            totp_secret: r.get("totp_secret"),
            totp_enrolled: r.get("totp_enrolled"),
            role: r.get("role"),
            active: r.get("active"),
            failed_attempts: r.get("failed_attempts"),
            lockout_until: r.get("lockout_until"),
        }
    }))
}

pub async fn list_all(db: &PgPool) -> Result<Vec<User>> {
    let rows = sqlx::query(
        "SELECT id, username, email, password_hash, totp_secret, totp_enrolled, role, active, failed_attempts, lockout_until
         FROM users ORDER BY username ASC"
    )
    .fetch_all(db)
    .await?;

    use sqlx::Row;
    Ok(rows.into_iter().map(|r| User {
        id: r.get("id"),
        username: r.get("username"),
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        totp_secret: r.get("totp_secret"),
        totp_enrolled: r.get("totp_enrolled"),
        role: r.get("role"),
        active: r.get("active"),
        failed_attempts: r.get("failed_attempts"),
        lockout_until: r.get("lockout_until"),
    }).collect())
}

pub async fn create_user(
    db: &PgPool,
    username: &str,
    email: &str,
    password_hash: &str,
    role: &str,
) -> Result<Uuid> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"INSERT INTO users (username, email, password_hash, role, active)
           VALUES ($1, $2, $3, $4, true)
           RETURNING id"#
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(role)
    .fetch_one(db)
    .await?;

    Ok(row.get("id"))
}

pub async fn deactivate_user(db: &PgPool, user_id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE users SET active = false WHERE id = $1 AND active = true"
    )
    .bind(user_id)
    .execute(db)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn update_password(db: &PgPool, user_id: Uuid, new_hash: &str) -> Result<()> {
    sqlx::query(
        "UPDATE users SET password_hash = $1 WHERE id = $2"
    )
    .bind(new_hash)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn increment_failed_attempts(db: &PgPool, username: &str) -> Result<i32> {
    let row = sqlx::query(
        r#"UPDATE users
           SET failed_attempts = failed_attempts + 1,
               lockout_until = CASE
                   WHEN failed_attempts + 1 >= 10 THEN NOW() + INTERVAL '1 hour'
                   WHEN failed_attempts + 1 >= 5  THEN NOW() + (INTERVAL '1 minute' * POWER(2, failed_attempts - 4)::int)
                   ELSE lockout_until
               END
           WHERE username = $1
           RETURNING failed_attempts"#
    )
    .bind(username)
    .fetch_optional(db)
    .await?;

    use sqlx::Row;
    Ok(row.map(|r| r.get::<i32, _>("failed_attempts")).unwrap_or(0))
}

pub async fn reset_failed_attempts(db: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE users SET failed_attempts = 0, lockout_until = NULL, last_login = NOW() WHERE id = $1"
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_totp_secret(db: &PgPool, user_id: Uuid, secret: &str) -> Result<()> {
    sqlx::query(
        "UPDATE users SET totp_secret = $1, totp_enrolled = true WHERE id = $2"
    )
    .bind(secret)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn ensure_admin(db: &PgPool, config: &Config) -> Result<()> {
    if config.admin_password.is_empty() || config.admin_email.is_empty() {
        tracing::warn!("ADMIN_PASSWORD or ADMIN_EMAIL not set — skipping admin bootstrap");
        return Ok(());
    }

    use sqlx::Row;
    let exists: bool = sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = 'admin')"
    )
    .fetch_one(db)
    .await?
    .get::<bool, _>(0);

    if !exists {
        let hash = crypto::hash_password(&config.admin_password)
            .map_err(|e| anyhow::anyhow!("Failed to hash admin password: {}", e))?;

        sqlx::query(
            r#"INSERT INTO users (username, email, password_hash, role, active)
               VALUES ('admin', $1, $2, 'admin', true)
               ON CONFLICT (username) DO NOTHING"#
        )
        .bind(&config.admin_email)
        .bind(&hash)
        .execute(db)
        .await?;

        tracing::info!("Admin user created: {}", config.admin_email);
    } else {
        tracing::info!("Admin user already exists");
    }

    Ok(())
}