//! SSH 服务模块
//!
//! 提供 SSH 连接管理和远程配置读取功能

use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// SSH 错误类型
#[derive(Error, Debug)]
pub enum SshError {
    #[error("SSH connection failed: {0}")]
    ConnectionFailed(String),
    #[error("SSH authentication failed: {0}")]
    AuthFailed(String),
    #[error("SSH command execution failed: {0}")]
    CommandFailed(String),
    #[error("File read failed: {0}")]
    FileReadFailed(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Server not connected")]
    NotConnected,
}

/// SSH 认证方式
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthType {
    Password,
    Key,
}

/// SSH 连接配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: SshAuthType,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub passphrase: Option<String>,
}

/// 远程服务器信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteServerInfo {
    pub id: String,
    pub name: String,
    pub ssh_config: SshConfig,
}

/// 连接状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
    Error,
}

/// 远程配置数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub providers: serde_json::Value,
    pub current_provider_id: Option<String>,
    pub proxy_target_provider_id: Option<String>,
}

/// SSH 服务
pub struct SshService {
    /// 活跃的 SSH 连接 (server_id -> client)
    connections: Arc<RwLock<HashMap<String, Client>>>,
    /// 连接状态 (server_id -> status)
    status: Arc<RwLock<HashMap<String, ConnectionStatus>>>,
}

impl SshService {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            status: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 连接到远程服务器
    pub async fn connect(&self, server_id: &str, config: &SshConfig) -> Result<(), SshError> {
        // 设置连接中状态
        {
            let mut status = self.status.write().await;
            status.insert(server_id.to_string(), ConnectionStatus::Connecting);
        }

        // 构建认证方法
        let auth_method = match &config.auth_type {
            SshAuthType::Password => {
                let password = config.password.clone().ok_or_else(|| {
                    SshError::InvalidConfig("Password required for password auth".to_string())
                })?;
                AuthMethod::with_password(&password)
            }
            SshAuthType::Key => {
                let key_path = config.private_key_path.clone().ok_or_else(|| {
                    SshError::InvalidConfig("Private key path required for key auth".to_string())
                })?;

                // 处理路径：展开 ~ 和处理特殊字符
                let key_path = if key_path.starts_with("~/") {
                    // 展开 ~ 到用户主目录
                    if let Some(home) = dirs::home_dir() {
                        home.join(&key_path[2..])
                    } else {
                        PathBuf::from(&key_path)
                    }
                } else if key_path == "~" {
                    dirs::home_dir().unwrap_or_else(|| PathBuf::from(&key_path))
                } else {
                    PathBuf::from(&key_path)
                };

                log::info!("Reading SSH key from: {:?}", key_path);

                // 读取私钥文件
                let private_key = tokio::fs::read_to_string(&key_path)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to read key file {:?}: {}", key_path, e);
                        SshError::InvalidConfig(format!("Failed to read key file '{}': {}", key_path.display(), e))
                    })?;

                log::info!("SSH key loaded, length: {} bytes", private_key.len());

                // 创建认证方法
                AuthMethod::with_key(&private_key, config.passphrase.as_deref())
            }
        };

        // 建立连接
        let client = Client::connect(
            (config.host.as_str(), config.port),
            &config.username,
            auth_method,
            ServerCheckMethod::NoCheck,
        )
        .await
        .map_err(|e| {
            // 设置错误状态
            let status = self.status.clone();
            let server_id = server_id.to_string();
            tokio::spawn(async move {
                let mut status = status.write().await;
                status.insert(server_id, ConnectionStatus::Error);
            });
            SshError::ConnectionFailed(e.to_string())
        })?;

        // 保存连接
        {
            let mut connections = self.connections.write().await;
            connections.insert(server_id.to_string(), client);
        }

        // 设置已连接状态
        {
            let mut status = self.status.write().await;
            status.insert(server_id.to_string(), ConnectionStatus::Connected);
        }

        log::info!("SSH connected to server: {}", server_id);
        Ok(())
    }

    /// 断开连接
    pub async fn disconnect(&self, server_id: &str) {
        {
            let mut connections = self.connections.write().await;
            connections.remove(server_id);
        }
        {
            let mut status = self.status.write().await;
            status.insert(server_id.to_string(), ConnectionStatus::Disconnected);
        }
        log::info!("SSH disconnected from server: {}", server_id);
    }

    /// 获取连接状态
    pub async fn get_status(&self, server_id: &str) -> ConnectionStatus {
        let status = self.status.read().await;
        status
            .get(server_id)
            .copied()
            .unwrap_or(ConnectionStatus::Disconnected)
    }

    /// 执行远程命令
    pub async fn execute(&self, server_id: &str, command: &str) -> Result<String, SshError> {
        let connections = self.connections.read().await;
        let client = connections
            .get(server_id)
            .ok_or(SshError::NotConnected)?;

        let result = client
            .execute(command)
            .await
            .map_err(|e| SshError::CommandFailed(e.to_string()))?;

        if result.exit_status != 0 {
            return Err(SshError::CommandFailed(format!(
                "Command exited with status {}: {}",
                result.exit_status, result.stderr
            )));
        }

        Ok(result.stdout)
    }

    /// 读取远程文件
    pub async fn read_file(&self, server_id: &str, path: &str) -> Result<String, SshError> {
        self.execute(server_id, &format!("cat {}", path)).await
    }

    /// 检查远程是否安装了 sqlite3
    async fn check_remote_sqlite3_installed(&self, server_id: &str) -> bool {
        match self.execute(server_id, "which sqlite3").await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// 确保远程目录存在
    async fn ensure_remote_dir(&self, server_id: &str, remote_path: &str) -> Result<(), SshError> {
        let parent = std::path::Path::new(remote_path).parent();
        if let Some(parent_path) = parent {
            if let Some(parent_str) = parent_path.to_str() {
                // 简单的 mkdir -p
                self.execute(server_id, &format!("mkdir -p '{}'", parent_str)).await?;
            }
        }
        Ok(())
    }

    /// 下载远程文件到本地
    /// 使用 cat + base64 方式 (假设远程有 cat 和 base64，如果没有 base64 则直接 cat，但需注意二进制安全)
    /// 为通用性，先尝试 base64，如果失败尝试直接 cat
    async fn download_file(&self, server_id: &str, remote_path: &str, local_path: &PathBuf) -> Result<(), SshError> {
        let content_base64 = match self.execute(server_id, &format!("cat '{}' | base64", remote_path)).await {
            Ok(output) => output,
            Err(_) => {
                 // 尝试直接读取 (可能不安全，但作为备选)
                 self.execute(server_id, &format!("cat '{}'", remote_path)).await?
            }
        };

        // 尝试解码 base64
        // 去除可能的换行符
        let cleaned = content_base64.replace("\n", "").replace("\r", "");
        use base64::Engine;
        let bytes = match base64::engine::general_purpose::STANDARD.decode(&cleaned) {
             Ok(b) => b,
             Err(_) => {
                 // 如果解码失败，假定它是 raw content (例如远程没有base64命令)
                 // 但这对于 sqlite db 文件极其危险。这里我们仅处理 base64 成功的情况。
                 // 如果远程连 base64 都没有，这个功能很难实现。
                 return Err(SshError::FileReadFailed("Failed to decode base64 file content from remote".to_string()));
             }
        };

        tokio::fs::write(local_path, bytes).await.map_err(|e| SshError::FileReadFailed(e.to_string()))?;
        Ok(())
    }

    /// 上传本地文件到远程
    /// 使用 base64 + decoding on remote
    async fn upload_file(&self, server_id: &str, local_path: &PathBuf, remote_path: &str) -> Result<(), SshError> {
        let bytes = tokio::fs::read(local_path).await.map_err(|e| SshError::FileReadFailed(e.to_string()))?;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);

        // 分块上传可能太复杂，这里假设文件不大，直接 echo
        // 注意命令行长度限制。如果文件大，需要 scp/sftp。这里暂且用 cat <<EOF > file 方式
        // 或者 echo "..." | base64 -d > file
        
        // 检查远程是否有 base64 -d 或 base64 --decode
        // Linux generic: base64 -d
        // Mac: base64 -D (有些版本)
        // 尝试通用: python/perl? 不，太重。
        // 我们假设 standard linux environment
        
        let cmd = format!("echo '{}' | base64 -d > '{}'", b64, remote_path);
        
        // 如果文件太大，cmd length 会爆。Config DB 通常很小。
        // CCS Panel config db 一般只有几KB到几十KB。
        if cmd.len() > 100_000 {
            return Err(SshError::CommandFailed("File too large for shell transfer".to_string()));
        }

        self.execute(server_id, &cmd).await.map(|_| ())
    }

    /// 查找远程数据库路径（仅查找，不创建，返回 path string）
    /// 依次检查标准路径
    async fn find_existing_db_path(&self, server_id: &str) -> Option<String> {
         let db_paths = vec![
            "~/.config/cc-switch/cc-switch.db",
            "~/Library/Application\\ Support/cc-switch/cc-switch.db",
            "~/.local/share/cc-switch/cc-switch.db",
        ];

        for path in &db_paths {
            let check_cmd = format!("ls -d {}", path);
            if let Ok(result) = self.execute(server_id, &check_cmd).await {
                let trimmed = result.trim();
                if !trimmed.is_empty() && !trimmed.contains("No such file") {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    /// 解决数据库路径：如果存在则返回，不存在则返回默认路径
    async fn resolve_db_path(&self, server_id: &str) -> String {
        if let Some(path) = self.find_existing_db_path(server_id).await {
            path
        } else {
             "~/.config/cc-switch/cc-switch.db".to_string()
        }
    }

    /// 读取远程 CCS Panel 配置
    pub async fn read_remote_config(
        &self,
        server_id: &str,
        app_type: &str,
    ) -> Result<RemoteConfig, SshError> {

        // 1. 检查 sqlite3
        if self.check_remote_sqlite3_installed(server_id).await {
            let db_path = self.resolve_db_path(server_id).await;

            // 检查文件是否存在，如果不存在直接返回默认空配置
            if self.find_existing_db_path(server_id).await.is_none() {
                 return Ok(RemoteConfig {
                    providers: serde_json::Value::Array(vec![]),
                    current_provider_id: None,
                    proxy_target_provider_id: None,
                });
            }

            // Query with all fields matching local database structure
             let query = format!(
                "sqlite3 '{}' \"SELECT json_group_array(json_object('id', id, 'name', name, 'app_type', app_type, 'settingsConfig', settings_config, 'websiteUrl', website_url, 'category', category, 'createdAt', created_at, 'sortIndex', sort_index, 'notes', notes, 'icon', icon, 'iconColor', icon_color, 'meta', meta, 'isCurrent', is_current, 'isProxyTarget', is_proxy_target)) FROM providers WHERE app_type = '{}'\"",
                db_path, app_type
            );

            match self.execute(server_id, &query).await {
                Ok(providers_json) => {
                     let providers: serde_json::Value = serde_json::from_str(&providers_json).unwrap_or(serde_json::Value::Array(vec![]));

                     let current_query = format!(
                        "sqlite3 '{}' \"SELECT id FROM providers WHERE app_type = '{}' AND is_current = 1 LIMIT 1\"",
                        db_path, app_type
                    );
                    let current_id = self.execute(server_id, &current_query).await.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

                    let proxy_target_query = format!(
                        "sqlite3 '{}' \"SELECT id FROM providers WHERE app_type = '{}' AND is_proxy_target = 1 LIMIT 1\"",
                        db_path, app_type
                    );
                    let proxy_target_id = self.execute(server_id, &proxy_target_query).await.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

                    return Ok(RemoteConfig {
                        providers,
                        current_provider_id: current_id,
                        proxy_target_provider_id: proxy_target_id,
                    });
                }
                Err(_) => {
                    // 如果 SQL 执行失败，可能是表不存在等，返回空
                    return Ok(RemoteConfig {
                        providers: serde_json::Value::Array(vec![]),
                        current_provider_id: None,
                        proxy_target_provider_id: None,
                    });
                }
            }
        }

        // 2. Fallback: Local processing
        log::info!("[read_remote_config] Loopback mode: sqlite3 not found on remote. Downloading DB.");
        let remote_path = self.resolve_db_path(server_id).await;

        // 如果远程连文件都不存在
        if self.find_existing_db_path(server_id).await.is_none() {
            return Ok(RemoteConfig {
                providers: serde_json::Value::Array(vec![]),
                current_provider_id: None,
                proxy_target_provider_id: None,
            });
        }

        let temp_dir = tempfile::tempdir().map_err(|e| SshError::FileReadFailed(e.to_string()))?;
        let local_path = temp_dir.path().join("cc-switch.db");

        self.download_file(server_id, &remote_path, &local_path).await?;

        // Open local DB
        let conn = rusqlite::Connection::open(&local_path).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

        // Query with all fields matching local database structure
        let mut stmt = conn.prepare(
            "SELECT id, name, settings_config, website_url, category, created_at, sort_index, notes, icon, icon_color, meta, is_current, is_proxy_target FROM providers WHERE app_type = ?"
        ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

        let rows = stmt.query_map([app_type], |row| {
             Ok(serde_json::json!({
                 "id": row.get::<_, String>(0)?,
                 "name": row.get::<_, String>(1)?,
                 "settingsConfig": row.get::<_, String>(2)?,
                 "websiteUrl": row.get::<_, Option<String>>(3)?,
                 "category": row.get::<_, Option<String>>(4)?,
                 "createdAt": row.get::<_, Option<i64>>(5)?,
                 "sortIndex": row.get::<_, Option<i64>>(6)?,
                 "notes": row.get::<_, Option<String>>(7)?,
                 "icon": row.get::<_, Option<String>>(8)?,
                 "iconColor": row.get::<_, Option<String>>(9)?,
                 "meta": row.get::<_, String>(10)?,
                 "isCurrent": row.get::<_, i64>(11)? == 1,
                 "isProxyTarget": row.get::<_, i64>(12)? == 1,
             }))
        }).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

        let providers: Vec<serde_json::Value> = rows.filter_map(Result::ok).collect();

        // Get current ID
        let mut current_stmt = conn.prepare("SELECT id FROM providers WHERE app_type = ? AND is_current = 1 LIMIT 1").map_err(|e| SshError::FileReadFailed(e.to_string()))?;
        let current_id: Option<String> = current_stmt.query_row([app_type], |row| row.get(0)).ok();

        // Get proxy target ID
        let mut proxy_target_stmt = conn.prepare("SELECT id FROM providers WHERE app_type = ? AND is_proxy_target = 1 LIMIT 1").map_err(|e| SshError::FileReadFailed(e.to_string()))?;
        let proxy_target_id: Option<String> = proxy_target_stmt.query_row([app_type], |row| row.get(0)).ok();

        Ok(RemoteConfig {
            providers: serde_json::Value::Array(providers),
            current_provider_id: current_id,
            proxy_target_provider_id: proxy_target_id,
        })
    }

    /// 添加远程供应商
    pub async fn add_remote_provider(
        &self,
        server_id: &str,
        provider: &serde_json::Value,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[add_remote_provider] Starting for server: {}", server_id);

        let remote_sqlite3_exists = self.check_remote_sqlite3_installed(server_id).await;
        let remote_db_path = self.resolve_db_path(server_id).await;

        // 准备 SQL 参数 - 完全匹配本地数据库结构
        let id = provider["id"].as_str().unwrap_or("").to_string();
        let name = provider["name"].as_str().unwrap_or("").to_string();
        let settings_config = provider["settingsConfig"].to_string();
        let category = provider["category"].as_str().map(|s| s.to_string());
        let website_url = provider["websiteUrl"].as_str().map(|s| s.to_string());
        let icon = provider["icon"].as_str().map(|s| s.to_string());
        let icon_color = provider["iconColor"].as_str().map(|s| s.to_string());
        let sort_index = provider["sortIndex"].as_i64();
        let notes = provider["notes"].as_str().map(|s| s.to_string());
        let created_at = provider["createdAt"].as_i64();
        // meta 字段需要序列化
        let meta = provider["meta"].to_string();
        let is_proxy_target = provider["isProxyTarget"].as_bool().unwrap_or(false);

        if remote_sqlite3_exists {
             // ... existing sqlite3 remote command logic ...
             // We use 'ensure_remote_dir' first to be safe
             self.ensure_remote_dir(server_id, &remote_db_path).await?;
             
            // Create schema if needed - matching local database structure exactly
             let create_table_sql = r#"CREATE TABLE IF NOT EXISTS providers (
                id TEXT NOT NULL,
                app_type TEXT NOT NULL,
                name TEXT NOT NULL,
                settings_config TEXT NOT NULL,
                website_url TEXT,
                category TEXT,
                created_at INTEGER,
                sort_index INTEGER,
                notes TEXT,
                icon TEXT,
                icon_color TEXT,
                meta TEXT NOT NULL DEFAULT '{}',
                is_current INTEGER NOT NULL DEFAULT 0,
                is_proxy_target INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (id, app_type)
            )"#;
            self.execute(server_id, &format!("sqlite3 '{}' \"{}\"", remote_db_path, create_table_sql)).await?;

            // Create provider_endpoints table - matching local structure
            let create_endpoints_sql = r#"CREATE TABLE IF NOT EXISTS provider_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_id TEXT NOT NULL,
                app_type TEXT NOT NULL,
                url TEXT NOT NULL,
                added_at INTEGER,
                FOREIGN KEY (provider_id, app_type) REFERENCES providers(id, app_type) ON DELETE CASCADE
            )"#;
            self.execute(server_id, &format!("sqlite3 '{}' \"{}\"", remote_db_path, create_endpoints_sql)).await?;

            // Insert - matching local database structure
             let sql_escape = |s: &str| s.replace("'", "''");
             let sql = format!(
                "INSERT INTO providers (id, app_type, name, settings_config, website_url, category, created_at, sort_index, notes, icon, icon_color, meta, is_current, is_proxy_target) VALUES ('{}', '{}', '{}', '{}', {}, {}, {}, {}, {}, {}, {}, '{}', 0, {})",
                sql_escape(&id),
                app_type,
                sql_escape(&name),
                sql_escape(&settings_config),
                website_url.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                category.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                created_at.map(|v| v.to_string()).unwrap_or("NULL".to_string()),
                sort_index.map(|v| v.to_string()).unwrap_or("NULL".to_string()),
                notes.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                icon.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                icon_color.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                sql_escape(&meta),
                if is_proxy_target { 1 } else { 0 }
            );
             self.execute(server_id, &format!("sqlite3 '{}' '{}'", remote_db_path, sql.replace("'", "'\\''"))).await.map(|_| ())
        } else {
             // Fallback: Download -> modify -> upload
             log::info!("[add_remote_provider] sqlite3 missing, swapping to local modify mode");

             let temp_dir = tempfile::tempdir().map_err(|e| SshError::FileReadFailed(e.to_string()))?;
             let local_path = temp_dir.path().join("cc-switch.db");

             // Check if remote DB exists
             if self.find_existing_db_path(server_id).await.is_some() {
                 self.download_file(server_id, &remote_db_path, &local_path).await?;
             }

             // Use local rusqlite to open/create
             let conn = rusqlite::Connection::open(&local_path).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

             // Ensure schema - matching local database structure exactly
             conn.execute(
                r#"CREATE TABLE IF NOT EXISTS providers (
                    id TEXT NOT NULL,
                    app_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    settings_config TEXT NOT NULL,
                    website_url TEXT,
                    category TEXT,
                    created_at INTEGER,
                    sort_index INTEGER,
                    notes TEXT,
                    icon TEXT,
                    icon_color TEXT,
                    meta TEXT NOT NULL DEFAULT '{}',
                    is_current INTEGER NOT NULL DEFAULT 0,
                    is_proxy_target INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (id, app_type)
                )"#,
                [],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            // Create provider_endpoints table
            conn.execute(
                r#"CREATE TABLE IF NOT EXISTS provider_endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider_id TEXT NOT NULL,
                    app_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    added_at INTEGER,
                    FOREIGN KEY (provider_id, app_type) REFERENCES providers(id, app_type) ON DELETE CASCADE
                )"#,
                [],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            // Insert - matching local database structure
            conn.execute(
                "INSERT INTO providers (id, app_type, name, settings_config, website_url, category, created_at, sort_index, notes, icon, icon_color, meta, is_current, is_proxy_target) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, ?13)",
                rusqlite::params![id, app_type, name, settings_config, website_url, category, created_at, sort_index, notes, icon, icon_color, meta, is_proxy_target],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            // Close connection explicitly (drop)
            drop(conn);

            // Upload
            self.ensure_remote_dir(server_id, &remote_db_path).await?;
            self.upload_file(server_id, &local_path, &remote_db_path).await?;

            Ok(())
        }
    }

    /// 更新远程供应商
    pub async fn update_remote_provider(
        &self,
        server_id: &str,
        provider: &serde_json::Value,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[update_remote_provider] Starting for server: {}", server_id);

        let remote_sqlite3_exists = self.check_remote_sqlite3_installed(server_id).await;
        let remote_db_path = self.resolve_db_path(server_id).await;

        // 准备 SQL 参数
        let id = provider["id"].as_str().unwrap_or("").to_string();
        let name = provider["name"].as_str().unwrap_or("").to_string();
        let settings_config = provider["settingsConfig"].to_string();
        let category = provider["category"].as_str().map(|s| s.to_string());
        let website_url = provider["websiteUrl"].as_str().map(|s| s.to_string());
        let icon = provider["icon"].as_str().map(|s| s.to_string());
        let icon_color = provider["iconColor"].as_str().map(|s| s.to_string());
        let sort_index = provider["sortIndex"].as_i64();
        let notes = provider["notes"].as_str().map(|s| s.to_string());
        let meta = provider["meta"].to_string();

        if remote_sqlite3_exists {
            let sql_escape = |s: &str| s.replace("'", "''");
            let sql = format!(
                "UPDATE providers SET name='{}', settings_config='{}', website_url={}, category={}, sort_index={}, notes={}, icon={}, icon_color={}, meta='{}' WHERE id='{}' AND app_type='{}'",
                sql_escape(&name),
                sql_escape(&settings_config),
                website_url.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                category.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                sort_index.map(|v| v.to_string()).unwrap_or("NULL".to_string()),
                notes.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                icon.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                icon_color.as_ref().map(|s| format!("'{}'", sql_escape(s))).unwrap_or("NULL".to_string()),
                sql_escape(&meta),
                sql_escape(&id),
                app_type
            );
            self.execute(server_id, &format!("sqlite3 '{}' '{}'", remote_db_path, sql.replace("'", "'\\''"))).await.map(|_| ())
        } else {
            // Fallback: Download -> modify -> upload
            log::info!("[update_remote_provider] sqlite3 missing, using local modify mode");

            let temp_dir = tempfile::tempdir().map_err(|e| SshError::FileReadFailed(e.to_string()))?;
            let local_path = temp_dir.path().join("cc-switch.db");

            self.download_file(server_id, &remote_db_path, &local_path).await?;

            let conn = rusqlite::Connection::open(&local_path).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            conn.execute(
                "UPDATE providers SET name=?1, settings_config=?2, website_url=?3, category=?4, sort_index=?5, notes=?6, icon=?7, icon_color=?8, meta=?9 WHERE id=?10 AND app_type=?11",
                rusqlite::params![name, settings_config, website_url, category, sort_index, notes, icon, icon_color, meta, id, app_type],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            drop(conn);

            self.upload_file(server_id, &local_path, &remote_db_path).await?;

            Ok(())
        }
    }

    /// 删除远程供应商
    pub async fn delete_remote_provider(
        &self,
        server_id: &str,
        provider_id: &str,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[delete_remote_provider] Starting for server: {}, provider: {}", server_id, provider_id);

        let remote_sqlite3_exists = self.check_remote_sqlite3_installed(server_id).await;
        let remote_db_path = self.resolve_db_path(server_id).await;

        if remote_sqlite3_exists {
            let sql_escape = |s: &str| s.replace("'", "''");
            let sql = format!(
                "DELETE FROM providers WHERE id='{}' AND app_type='{}'",
                sql_escape(provider_id),
                app_type
            );
            self.execute(server_id, &format!("sqlite3 '{}' '{}'", remote_db_path, sql.replace("'", "'\\''"))).await.map(|_| ())
        } else {
            let temp_dir = tempfile::tempdir().map_err(|e| SshError::FileReadFailed(e.to_string()))?;
            let local_path = temp_dir.path().join("cc-switch.db");

            self.download_file(server_id, &remote_db_path, &local_path).await?;

            let conn = rusqlite::Connection::open(&local_path).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            conn.execute(
                "DELETE FROM providers WHERE id=?1 AND app_type=?2",
                rusqlite::params![provider_id, app_type],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            drop(conn);

            self.upload_file(server_id, &local_path, &remote_db_path).await?;

            Ok(())
        }
    }

    /// 设置远程当前供应商
    pub async fn set_remote_current_provider(
        &self,
        server_id: &str,
        provider_id: &str,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[set_remote_current_provider] Starting for server: {}, provider: {}", server_id, provider_id);

        let remote_sqlite3_exists = self.check_remote_sqlite3_installed(server_id).await;
        let remote_db_path = self.resolve_db_path(server_id).await;

        if remote_sqlite3_exists {
            let sql_escape = |s: &str| s.replace("'", "''");
            // 先重置所有为 0，再设置指定的为 1
            let sql = format!(
                "UPDATE providers SET is_current=0 WHERE app_type='{}'; UPDATE providers SET is_current=1 WHERE id='{}' AND app_type='{}'",
                app_type,
                sql_escape(provider_id),
                app_type
            );
            self.execute(server_id, &format!("sqlite3 '{}' '{}'", remote_db_path, sql.replace("'", "'\\''"))).await.map(|_| ())
        } else {
            let temp_dir = tempfile::tempdir().map_err(|e| SshError::FileReadFailed(e.to_string()))?;
            let local_path = temp_dir.path().join("cc-switch.db");

            self.download_file(server_id, &remote_db_path, &local_path).await?;

            let conn = rusqlite::Connection::open(&local_path).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            conn.execute(
                "UPDATE providers SET is_current=0 WHERE app_type=?1",
                rusqlite::params![app_type],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            conn.execute(
                "UPDATE providers SET is_current=1 WHERE id=?1 AND app_type=?2",
                rusqlite::params![provider_id, app_type],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            drop(conn);

            self.upload_file(server_id, &local_path, &remote_db_path).await?;

            Ok(())
        }
    }

    /// 设置远程代理目标供应商
    pub async fn set_remote_proxy_target(
        &self,
        server_id: &str,
        provider_id: &str,
        app_type: &str,
        enabled: bool,
    ) -> Result<(), SshError> {
        log::info!("[set_remote_proxy_target] Starting for server: {}, provider: {}, enabled: {}", server_id, provider_id, enabled);

        let remote_sqlite3_exists = self.check_remote_sqlite3_installed(server_id).await;
        let remote_db_path = self.resolve_db_path(server_id).await;

        if remote_sqlite3_exists {
            let sql_escape = |s: &str| s.replace("'", "''");
            let sql = format!(
                "UPDATE providers SET is_proxy_target={} WHERE id='{}' AND app_type='{}'",
                if enabled { 1 } else { 0 },
                sql_escape(provider_id),
                app_type
            );
            self.execute(server_id, &format!("sqlite3 '{}' '{}'", remote_db_path, sql.replace("'", "'\\''"))).await.map(|_| ())
        } else {
            let temp_dir = tempfile::tempdir().map_err(|e| SshError::FileReadFailed(e.to_string()))?;
            let local_path = temp_dir.path().join("cc-switch.db");

            self.download_file(server_id, &remote_db_path, &local_path).await?;

            let conn = rusqlite::Connection::open(&local_path).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            conn.execute(
                "UPDATE providers SET is_proxy_target=?1 WHERE id=?2 AND app_type=?3",
                rusqlite::params![if enabled { 1 } else { 0 }, provider_id, app_type],
            ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

            drop(conn);

            self.upload_file(server_id, &local_path, &remote_db_path).await?;

            Ok(())
        }
    }

    /// 测试 SSH 连接
    pub async fn test_connection(&self, config: &SshConfig) -> Result<(), SshError> {
        let auth_method = match &config.auth_type {
            SshAuthType::Password => {
                let password = config.password.clone().ok_or_else(|| {
                    SshError::InvalidConfig("Password required for password auth".to_string())
                })?;
                AuthMethod::with_password(&password)
            }
            SshAuthType::Key => {
                let key_path = config.private_key_path.clone().ok_or_else(|| {
                    SshError::InvalidConfig("Private key path required for key auth".to_string())
                })?;

                // 处理路径：展开 ~ 和处理特殊字符
                let key_path = if key_path.starts_with("~/") {
                    if let Some(home) = dirs::home_dir() {
                        home.join(&key_path[2..])
                    } else {
                        PathBuf::from(&key_path)
                    }
                } else if key_path == "~" {
                    dirs::home_dir().unwrap_or_else(|| PathBuf::from(&key_path))
                } else {
                    PathBuf::from(&key_path)
                };

                log::info!("Testing SSH key from: {:?}", key_path);

                let private_key = tokio::fs::read_to_string(&key_path)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to read key file {:?}: {}", key_path, e);
                        SshError::InvalidConfig(format!("Failed to read key file '{}': {}", key_path.display(), e))
                    })?;

                AuthMethod::with_key(&private_key, config.passphrase.as_deref())
            }
        };

        // 尝试连接
        let client = Client::connect(
            (config.host.as_str(), config.port),
            &config.username,
            auth_method,
            ServerCheckMethod::NoCheck,
        )
        .await
        .map_err(|e| SshError::ConnectionFailed(e.to_string()))?;

        // 执行简单命令验证连接
        let result = client
            .execute("echo 'connection test'")
            .await
            .map_err(|e| SshError::CommandFailed(e.to_string()))?;

        if result.exit_status != 0 {
            return Err(SshError::CommandFailed(
                "Test command failed".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for SshService {
    fn default() -> Self {
        Self::new()
    }
}
