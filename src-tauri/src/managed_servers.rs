use crate::config::{get_app_config_dir, read_json_file, write_json_file};
use crate::error::AppError;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub type ManagedServersMap = HashMap<String, ManagedServer>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteConfigDirs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_config_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex_config_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_config_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,
    #[serde(skip_serializing)]
    pub passphrase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite3_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedServer {
    pub id: String,
    pub name: String,
    pub connection_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_config: Option<SshConfig>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connected: Option<i64>,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_local: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_dirs: Option<RemoteConfigDirs>,
}

const LOCAL_SERVER_ID: &str = "local";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn create_local_server() -> ManagedServer {
    ManagedServer {
        id: LOCAL_SERVER_ID.to_string(),
        name: "本地服务器".to_string(),
        connection_type: "local".to_string(),
        ssh_config: None,
        status: "connected".to_string(),
        last_connected: None,
        created_at: now_ms(),
        is_local: Some(true),
        config_dirs: None,
    }
}

pub fn servers_json_path() -> PathBuf {
    get_app_config_dir().join("servers.json")
}

fn secrets_db_path() -> PathBuf {
    get_app_config_dir().join("servers.db")
}

fn open_secrets_db() -> Result<Connection, AppError> {
    let path = secrets_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| AppError::io(parent, e))?;
    }

    let conn = Connection::open(&path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS server_secrets (
          server_id  TEXT PRIMARY KEY,
          password   TEXT,
          passphrase TEXT,
          updated_at INTEGER NOT NULL
        );
        "#,
    )?;
    Ok(conn)
}

fn read_secret(conn: &Connection, server_id: &str) -> Result<(Option<String>, Option<String>), AppError> {
    let mut stmt = conn.prepare(
        "SELECT password, passphrase FROM server_secrets WHERE server_id = ?1 LIMIT 1",
    )?;
    let mut rows = stmt.query(params![server_id])?;
    if let Some(row) = rows.next()? {
        let password: Option<String> = row.get(0)?;
        let passphrase: Option<String> = row.get(1)?;
        return Ok((password, passphrase));
    }
    Ok((None, None))
}

fn upsert_secret(
    conn: &Connection,
    server_id: &str,
    password: Option<&str>,
    passphrase: Option<&str>,
) -> Result<(), AppError> {
    conn.execute(
        r#"
        INSERT INTO server_secrets (server_id, password, passphrase, updated_at)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(server_id) DO UPDATE SET
          password   = excluded.password,
          passphrase = excluded.passphrase,
          updated_at = excluded.updated_at
        "#,
        params![server_id, password, passphrase, now_ms()],
    )?;
    Ok(())
}

fn delete_secret(conn: &Connection, server_id: &str) -> Result<(), AppError> {
    conn.execute(
        "DELETE FROM server_secrets WHERE server_id = ?1",
        params![server_id],
    )?;
    Ok(())
}

fn list_secret_ids(conn: &Connection) -> Result<Vec<String>, AppError> {
    let mut stmt = conn.prepare("SELECT server_id FROM server_secrets")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut ids = Vec::new();
    for id in rows {
        ids.push(id?);
    }
    Ok(ids)
}

#[cfg(unix)]
fn set_owner_only_perms(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_owner_only_perms(_path: &PathBuf) {}

fn normalize_loaded_servers(mut servers: ManagedServersMap) -> ManagedServersMap {
    if !servers.contains_key(LOCAL_SERVER_ID) {
        servers.insert(LOCAL_SERVER_ID.to_string(), create_local_server());
    }

    // 远程服务器启动时重置为未连接状态（保持与旧行为一致）
    for (id, server) in servers.iter_mut() {
        if id != LOCAL_SERVER_ID {
            server.status = "disconnected".to_string();
        }
        // 修正 id 字段（以 map key 为准）
        server.id = id.clone();
    }

    servers
}

pub fn load_managed_servers() -> Result<ManagedServersMap, AppError> {
    let path = servers_json_path();

    let mut servers: ManagedServersMap = if path.exists() {
        match read_json_file(&path) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[managed_servers] 读取 servers.json 失败，将回退到默认值: {e}");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    servers = normalize_loaded_servers(servers);

    // 合并 secrets（如果存在）
    let conn = open_secrets_db()?;
    for (id, server) in servers.iter_mut() {
        if id == LOCAL_SERVER_ID {
            continue;
        }
        let Some(ssh) = server.ssh_config.as_mut() else {
            continue;
        };
        let (password, passphrase) = read_secret(&conn, id)?;
        ssh.password = password;
        ssh.passphrase = passphrase;
    }

    Ok(servers)
}

pub fn save_managed_servers(mut servers: ManagedServersMap) -> Result<(), AppError> {
    servers = normalize_loaded_servers(servers);

    let path = servers_json_path();
    let conn = open_secrets_db()?;

    // 同步 secrets
    let present: HashSet<String> = servers.keys().cloned().collect();
    for existing_id in list_secret_ids(&conn)? {
        if !present.contains(&existing_id) {
            let _ = delete_secret(&conn, &existing_id);
        }
    }

    for (id, server) in servers.iter() {
        if id == LOCAL_SERVER_ID {
            continue;
        }
        let Some(ssh) = server.ssh_config.as_ref() else {
            let _ = delete_secret(&conn, id);
            continue;
        };

        let password = ssh
            .password
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let passphrase = ssh
            .passphrase
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if password.is_none() && passphrase.is_none() {
            let _ = delete_secret(&conn, id);
        } else {
            upsert_secret(&conn, id, password, passphrase)?;
        }
    }

    // 写入 servers.json（password/passphrase 会被 skip_serializing 自动剔除）
    write_json_file(&path, &servers)?;
    set_owner_only_perms(&path);

    let db_path = secrets_db_path();
    set_owner_only_perms(&db_path);

    Ok(())
}

