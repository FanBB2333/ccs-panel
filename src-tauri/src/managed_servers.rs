use crate::config::get_app_config_dir;
use crate::error::AppError;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
const STATE_ROW_ID: i64 = 1;

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

fn servers_db_path() -> PathBuf {
    get_app_config_dir().join("servers.db")
}

fn open_servers_db() -> Result<(Connection, PathBuf), AppError> {
    let path = servers_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| AppError::io(parent, e))?;
    }

    let conn = Connection::open(&path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS managed_servers_state (
          id         INTEGER PRIMARY KEY CHECK (id = 1),
          data       TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );
        "#,
    )?;
    Ok((conn, path))
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
    let (conn, _path) = open_servers_db()?;

    let stored: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT data FROM managed_servers_state WHERE id = ?1",
        params![STATE_ROW_ID],
        |row| row.get(0),
    );

    let servers: ManagedServersMap = match stored {
        Ok(json) => serde_json::from_str(&json).map_err(|e| {
            AppError::Config(format!("解析 servers.db 中的服务器数据失败: {e}"))
        })?,
        Err(rusqlite::Error::QueryReturnedNoRows) => HashMap::new(),
        Err(e) => return Err(AppError::from(e)),
    };

    Ok(normalize_loaded_servers(servers))
}

pub fn save_managed_servers(mut servers: ManagedServersMap) -> Result<(), AppError> {
    servers = normalize_loaded_servers(servers);

    let (conn, db_path) = open_servers_db()?;
    let json = serde_json::to_string(&servers)
        .map_err(|e| AppError::JsonSerialize { source: e })?;

    conn.execute(
        r#"
        INSERT INTO managed_servers_state (id, data, updated_at)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(id) DO UPDATE SET
          data = excluded.data,
          updated_at = excluded.updated_at
        "#,
        params![STATE_ROW_ID, json, now_ms()],
    )?;

    set_owner_only_perms(&db_path);

    Ok(())
}
