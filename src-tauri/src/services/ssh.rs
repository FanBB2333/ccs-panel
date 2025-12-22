//! SSH 服务模块
//!
//! 提供 SSH 连接管理和远程配置读取功能

use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Child;
use std::str::FromStr;
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
    #[error("Port forwarding failed: {0}")]
    PortForwardingFailed(String),
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
    /// 远程 sqlite3 可执行文件路径（可选，如 /usr/bin/sqlite3 或 /home/user/.local/bin/sqlite3）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite3_path: Option<String>,
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

/// 端口转发状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardingStatus {
    /// 是否正在运行
    pub is_active: bool,
    /// 本地地址 (例如 127.0.0.1:5000)
    pub local_address: String,
    /// 远程端口
    pub remote_port: u16,
}

/// SSH 服务
#[derive(Clone)]
pub struct SshService {
    /// 活跃的 SSH 连接 (server_id -> client)
    connections: Arc<RwLock<HashMap<String, Client>>>,
    /// 连接状态 (server_id -> status)
    status: Arc<RwLock<HashMap<String, ConnectionStatus>>>,
    /// 服务器配置 (server_id -> config)
    configs: Arc<RwLock<HashMap<String, SshConfig>>>,
    /// 端口转发进程 (server_id -> child process)
    port_forwards: Arc<RwLock<HashMap<String, Child>>>,
    /// 端口转发状态 (server_id -> status)
    port_forward_status: Arc<RwLock<HashMap<String, PortForwardingStatus>>>,
}

impl SshService {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            status: Arc::new(RwLock::new(HashMap::new())),
            configs: Arc::new(RwLock::new(HashMap::new())),
            port_forwards: Arc::new(RwLock::new(HashMap::new())),
            port_forward_status: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 为 shell 命令正确引用路径
    ///
    /// 关键点：`~` 只有在单词开头且不在引号内时才会被 shell 展开。
    /// - `"~/path"` → ~ 不会展开（错误）
    /// - `~/path` → ~ 会展开，但路径有空格时会出问题
    /// - `~/"path with spaces"` → ~ 会展开且空格被正确处理（正确）
    fn quote_path_for_shell(path: &str) -> String {
        if path.starts_with("~/") {
            // 保持 ~ 在引号外以便 shell 展开，引号包裹其余部分处理空格
            format!("~/\"{}\"", &path[2..])
        } else {
            // 对于其他路径，直接用双引号包裹
            format!("\"{}\"", path)
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

        // 保存配置（用于后续获取 sqlite3_path 等信息）
        {
            let mut configs = self.configs.write().await;
            configs.insert(server_id.to_string(), config.clone());
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
            let mut configs = self.configs.write().await;
            configs.remove(server_id);
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

    /// 获取有效的 sqlite3 可执行路径
    /// 如果配置了自定义路径且可用，返回自定义路径；否则尝试系统默认路径
    async fn get_sqlite3_path(&self, server_id: &str) -> Option<String> {
        // 首先检查配置中是否有自定义路径
        let custom_path = {
            let configs = self.configs.read().await;
            configs.get(server_id).and_then(|c| c.sqlite3_path.clone())
        };

        if let Some(path) = custom_path {
            if !path.is_empty() {
                // 验证自定义路径是否可用
                let check_cmd = format!("test -x '{}' && echo 'ok'", path);
                if let Ok(output) = self.execute(server_id, &check_cmd).await {
                    if output.trim() == "ok" {
                        log::info!("[get_sqlite3_path] Using custom sqlite3 path: {}", path);
                        return Some(path);
                    } else {
                        log::warn!("[get_sqlite3_path] Custom sqlite3 path not executable: {}", path);
                    }
                }
            }
        }

        // 尝试系统默认路径
        if let Ok(output) = self.execute(server_id, "which sqlite3").await {
            let system_path = output.trim().to_string();
            if !system_path.is_empty() {
                log::info!("[get_sqlite3_path] Using system sqlite3 path: {}", system_path);
                return Some(system_path);
            }
        }

        // 尝试常见的 sqlite3 路径
        let common_paths = [
            "/usr/bin/sqlite3",
            "/usr/local/bin/sqlite3",
            "/opt/homebrew/bin/sqlite3",
            "~/.local/bin/sqlite3",
        ];

        for path in &common_paths {
            // 使用 quote_path_for_shell 正确处理 ~ 展开
            let quoted_path = Self::quote_path_for_shell(path);
            let check_cmd = format!("test -x {} && echo 'ok'", quoted_path);
            if let Ok(output) = self.execute(server_id, &check_cmd).await {
                if output.trim() == "ok" {
                    log::info!("[get_sqlite3_path] Found sqlite3 at: {}", path);
                    return Some(path.to_string());
                }
            }
        }

        log::warn!("[get_sqlite3_path] No sqlite3 found on remote server: {}", server_id);
        None
    }

    /// 检查远程是否安装了 sqlite3（返回路径或 None）
    pub async fn check_remote_sqlite3(&self, server_id: &str) -> Option<String> {
        self.get_sqlite3_path(server_id).await
    }

    /// 确保远程目录存在
    pub async fn ensure_remote_dir(&self, server_id: &str, remote_path: &str) -> Result<(), SshError> {
        let parent = std::path::Path::new(remote_path).parent();
        if let Some(parent_path) = parent {
            if let Some(parent_str) = parent_path.to_str() {
                // 注意：~ 在引号内不会被展开，需要保持 ~ 在引号外
                log::info!("[ensure_remote_dir] Creating directory: {}", parent_str);
                let quoted_path = Self::quote_path_for_shell(parent_str);
                self.execute(server_id, &format!("mkdir -p {}", quoted_path)).await?;
            }
        }
        Ok(())
    }

    /// 下载远程文件到本地
    /// 使用 cat + base64 方式 (假设远程有 cat 和 base64，如果没有 base64 则直接 cat，但需注意二进制安全)
    /// 为通用性，先尝试 base64，如果失败尝试直接 cat
    async fn download_file(&self, server_id: &str, remote_path: &str, local_path: &PathBuf) -> Result<(), SshError> {
        // 注意：~ 在引号内不会被展开，使用 quote_path_for_shell 正确处理
        let quoted_path = Self::quote_path_for_shell(remote_path);
        let content_base64 = match self.execute(server_id, &format!("cat {} | base64", quoted_path)).await {
            Ok(output) => output,
            Err(_) => {
                 // 尝试直接读取 (可能不安全，但作为备选)
                 self.execute(server_id, &format!("cat {}", quoted_path)).await?
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

        // 使用 quote_path_for_shell 正确处理 ~ 展开
        // echo 的内容使用单引号（不需要展开）
        let quoted_path = Self::quote_path_for_shell(remote_path);
        let cmd = format!("echo '{}' | base64 -d > {}", b64, quoted_path);
        
        // 如果文件太大，cmd length 会爆。Config DB 通常很小。
        if cmd.len() > 100_000 {
            return Err(SshError::CommandFailed("File too large for shell transfer".to_string()));
        }

        self.execute(server_id, &cmd).await.map(|_| ())
    }

    /// 查找远程数据库路径（仅查找，不创建，返回 path string）
    /// 依次检查标准路径，返回原始的 ~ 路径格式以保证跨用户一致性
    async fn find_existing_db_path(&self, server_id: &str) -> Option<String> {
         let db_paths = vec![
            // 首先检查本地默认路径（~/.cc-switch/）
            "~/.cc-switch/cc-switch.db",
            // 然后检查 XDG 标准路径
            "~/.config/cc-switch/cc-switch.db",
            "~/Library/Application Support/cc-switch/cc-switch.db",
            "~/.local/share/cc-switch/cc-switch.db",
        ];

        for path in &db_paths {
            // 使用 quote_path_for_shell 正确处理 ~ 展开
            let quoted_path = Self::quote_path_for_shell(path);
            let check_cmd = format!("test -f {} && echo 'exists'", quoted_path);
            log::info!("[find_existing_db_path] Checking: {} (cmd: {})", path, check_cmd);

            match self.execute(server_id, &check_cmd).await {
                Ok(result) => {
                    let trimmed = result.trim();
                    log::info!("[find_existing_db_path] Result for {}: '{}'", path, trimmed);
                    if trimmed == "exists" {
                        // 返回原始的 ~ 路径格式，保证跨用户一致性
                        return Some(path.to_string());
                    }
                }
                Err(e) => {
                    // test 失败表示文件不存在
                    log::info!("[find_existing_db_path] Not found at {}: {:?}", path, e);
                }
            }
        }
        None
    }

    /// 解决数据库路径：优先使用用户配置的工作目录，否则查找现有路径，最后返回默认路径
    pub async fn resolve_db_path(&self, server_id: &str) -> String {
        // 1. 优先使用用户配置的工作目录
        if let Some(working_dir) = crate::server_settings::get_server_working_dir(server_id) {
            log::info!(
                "[resolve_db_path] Using configured working_dir for server {}: {}",
                server_id,
                working_dir
            );
            return working_dir;
        }

        // 2. 查找现有的数据库路径
        if let Some(path) = self.find_existing_db_path(server_id).await {
            return path;
        }

        // 3. 默认使用 ~/.cc-switch/cc-switch.db（与本地一致）
        "~/.cc-switch/cc-switch.db".to_string()
    }

    /// 读取远程 CCS Panel 配置
    pub async fn read_remote_config(
        &self,
        server_id: &str,
        app_type: &str,
    ) -> Result<RemoteConfig, SshError> {

        // 1. 检查 sqlite3 是否可用（返回路径或 None）
        if let Some(sqlite3_path) = self.check_remote_sqlite3(server_id).await {
            let db_path = self.resolve_db_path(server_id).await;
            let quoted_db_path = Self::quote_path_for_shell(&db_path);

            // 检查文件是否存在，如果不存在直接返回默认空配置
            let existing_path = self.find_existing_db_path(server_id).await;
            if existing_path.is_none() {
                 log::warn!("[read_remote_config] No existing DB found, returning empty config");
                 return Ok(RemoteConfig {
                    providers: serde_json::Value::Array(vec![]),
                    current_provider_id: None,
                    proxy_target_provider_id: None,
                });
            }
            log::info!("[read_remote_config] Found DB at: {:?}", existing_path);

            // Query with all fields matching frontend expected format
            // Use camelCase field names to match Provider struct's serde rename attributes
             let query = format!(
                "{} {} \"SELECT json_group_array(json_object('id', id, 'name', name, 'appType', app_type, 'settingsConfig', settings_config, 'websiteUrl', website_url, 'category', category, 'createdAt', created_at, 'sortIndex', sort_index, 'notes', notes, 'icon', icon, 'iconColor', icon_color, 'meta', meta, 'isCurrent', is_current, 'isProxyTarget', is_proxy_target)) FROM providers WHERE app_type = '{}'\"",
                sqlite3_path, quoted_db_path, app_type
            );

            log::info!("[read_remote_config] Executing query: {}", query);

            match self.execute(server_id, &query).await {
                Ok(providers_json) => {
                    log::info!("[read_remote_config] Raw JSON from remote: {}", providers_json);

                     let providers: serde_json::Value = serde_json::from_str(&providers_json).map_err(|e| {
                         log::error!("[read_remote_config] JSON parse error: {}. Content: {}", e, providers_json);
                         SshError::FileReadFailed(format!("Failed to parse providers JSON from remote: {}", e))
                     })?;

                     let current_query = format!(
                        "{} {} \"SELECT id FROM providers WHERE app_type = '{}' AND is_current = 1 LIMIT 1\"",
                        sqlite3_path, quoted_db_path, app_type
                    );
                    let current_id = self.execute(server_id, &current_query).await.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

                    let proxy_target_query = format!(
                        "{} {} \"SELECT id FROM providers WHERE app_type = '{}' AND is_proxy_target = 1 LIMIT 1\"",
                        sqlite3_path, quoted_db_path, app_type
                    );
                    let proxy_target_id = self.execute(server_id, &proxy_target_query).await.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

                    return Ok(RemoteConfig {
                        providers,
                        current_provider_id: current_id,
                        proxy_target_provider_id: proxy_target_id,
                    });
                }
                Err(e) => {
                    log::error!("[read_remote_config] SQL execution failed: {}", e);
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

        // Query with all fields matching frontend expected format
        let mut stmt = conn.prepare(
            "SELECT id, name, settings_config, website_url, category, created_at, sort_index, notes, icon, icon_color, meta, is_current, is_proxy_target FROM providers WHERE app_type = ?"
        ).map_err(|e| SshError::FileReadFailed(e.to_string()))?;

        // Use camelCase field names to match Provider struct's serde rename attributes
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
    ///
    /// 使用 ProviderService::add_with_store 复用验证和保存逻辑
    pub async fn add_remote_provider(
        &self,
        server_id: &str,
        provider: &serde_json::Value,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[add_remote_provider] Starting for server: {}", server_id);

        // Parse provider from JSON
        let id = provider["id"].as_str().unwrap_or("").to_string();
        let parsed_provider = Provider::from_db_json(provider, id)
            .map_err(|e| SshError::InvalidConfig(format!("Failed to parse provider: {}", e)))?;

        // Create store and use ProviderService
        let store = RemoteProviderStore::new(self, server_id.to_string());
        let app_type_enum = crate::app_config::AppType::from_str(app_type)
            .map_err(|e| SshError::InvalidConfig(e.to_string()))?;

        crate::services::provider::ProviderService::add_with_store(&store, app_type_enum, parsed_provider)
            .map_err(|e| SshError::CommandFailed(format!("Failed to add provider: {}", e)))?;

        log::info!("[add_remote_provider] Successfully added provider on server {}", server_id);
        Ok(())
    }

    /// 更新远程供应商
    ///
    /// 使用 ProviderService::update_with_store 复用验证和保存逻辑
    pub async fn update_remote_provider(
        &self,
        server_id: &str,
        provider: &serde_json::Value,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[update_remote_provider] Starting for server: {}", server_id);

        // Parse provider from JSON
        let id = provider["id"].as_str().unwrap_or("").to_string();
        let parsed_provider = Provider::from_db_json(provider, id)
            .map_err(|e| SshError::InvalidConfig(format!("Failed to parse provider: {}", e)))?;

        // Create store and use ProviderService
        let store = RemoteProviderStore::new(self, server_id.to_string());
        let app_type_enum = crate::app_config::AppType::from_str(app_type)
            .map_err(|e| SshError::InvalidConfig(e.to_string()))?;

        crate::services::provider::ProviderService::update_with_store(&store, app_type_enum, parsed_provider)
            .map_err(|e| SshError::CommandFailed(format!("Failed to update provider: {}", e)))?;

        log::info!("[update_remote_provider] Successfully updated provider on server {}", server_id);
        Ok(())
    }

    /// 删除远程供应商
    ///
    /// 使用 ProviderService::delete_with_store 复用删除逻辑
    pub async fn delete_remote_provider(
        &self,
        server_id: &str,
        provider_id: &str,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[delete_remote_provider] Starting for server: {}, provider: {}", server_id, provider_id);

        // Create store and use ProviderService
        let store = RemoteProviderStore::new(self, server_id.to_string());
        let app_type_enum = crate::app_config::AppType::from_str(app_type)
            .map_err(|e| SshError::InvalidConfig(e.to_string()))?;

        crate::services::provider::ProviderService::delete_with_store(&store, app_type_enum, provider_id)
            .map_err(|e| SshError::CommandFailed(format!("Failed to delete provider: {}", e)))?;

        log::info!("[delete_remote_provider] Successfully deleted provider {} on server {}", provider_id, server_id);
        Ok(())
    }

    /// 设置远程当前供应商
    ///
    /// 使用 ProviderService::switch_with_store 复用切换逻辑
    pub async fn set_remote_current_provider(
        &self,
        server_id: &str,
        provider_id: &str,
        app_type: &str,
    ) -> Result<(), SshError> {
        log::info!("[set_remote_current_provider] Starting for server: {}, provider: {}, app_type: {}", server_id, provider_id, app_type);

        // Create store and use ProviderService
        let store = RemoteProviderStore::new(self, server_id.to_string());
        let app_type_enum = crate::app_config::AppType::from_str(app_type)
            .map_err(|e| SshError::InvalidConfig(e.to_string()))?;

        crate::services::provider::ProviderService::switch_with_store(&store, app_type_enum, provider_id)
            .map_err(|e| SshError::CommandFailed(format!("Failed to switch provider: {}", e)))?;

        log::info!("[set_remote_current_provider] Successfully switched provider {} on server {}", provider_id, server_id);
        Ok(())
    }

    /// 将 settings_config 写入远程的 live 配置文件
    pub async fn write_remote_live_config(
        &self,
        server_id: &str,
        app_type: &str,
        settings_config: &serde_json::Value,
    ) -> Result<(), SshError> {
        log::info!("[write_remote_live_config] Writing live config for app_type: {}", app_type);

        match app_type {
            "claude" => {
                // Claude: Write to ~/.claude/settings.json (or custom path)
                let claude_dir = crate::server_settings::get_server_claude_config_dir(server_id)
                    .unwrap_or_else(|| "~/.claude".to_string());
                let config_json = serde_json::to_string_pretty(settings_config)
                    .map_err(|e| SshError::InvalidConfig(format!("Failed to serialize config: {}", e)))?;

                // Create directory if not exists
                let mkdir_cmd = format!("mkdir -p {}", Self::quote_path_for_shell(&claude_dir));
                self.execute(server_id, &mkdir_cmd).await?;

                // Write config using heredoc to handle special characters
                let settings_path = format!("{}/settings.json", claude_dir);
                let cmd = format!(
                    "cat > {} << 'EOFCONFIG'\n{}\nEOFCONFIG",
                    Self::quote_path_for_shell(&settings_path),
                    config_json
                );
                self.execute(server_id, &cmd).await?;
                log::info!("[write_remote_live_config] Wrote Claude settings.json to {}", settings_path);
            }
            "codex" => {
                // Codex: Write auth.json and config.toml separately
                let codex_dir = crate::server_settings::get_server_codex_config_dir(server_id)
                    .unwrap_or_else(|| "~/.codex".to_string());
                let obj = settings_config.as_object().ok_or_else(|| {
                    SshError::InvalidConfig("Codex config must be a JSON object".to_string())
                })?;

                // Write auth.json
                if let Some(auth) = obj.get("auth") {
                    let auth_json = serde_json::to_string_pretty(auth)
                        .map_err(|e| SshError::InvalidConfig(format!("Failed to serialize auth: {}", e)))?;

                    let mkdir_cmd = format!("mkdir -p {}", Self::quote_path_for_shell(&codex_dir));
                    self.execute(server_id, &mkdir_cmd).await?;

                    let auth_path = format!("{}/auth.json", codex_dir);
                    let cmd = format!(
                        "cat > {} << 'EOFCONFIG'\n{}\nEOFCONFIG",
                        Self::quote_path_for_shell(&auth_path),
                        auth_json
                    );
                    self.execute(server_id, &cmd).await?;
                    log::info!("[write_remote_live_config] Wrote Codex auth.json to {}", auth_path);
                }

                // Write config.toml (optional)
                if let Some(config) = obj.get("config").and_then(|v| v.as_str()) {
                    let mkdir_cmd = format!("mkdir -p {}", Self::quote_path_for_shell(&codex_dir));
                    self.execute(server_id, &mkdir_cmd).await?;

                    let config_path = format!("{}/config.toml", codex_dir);
                    let cmd = format!(
                        "cat > {} << 'EOFCONFIG'\n{}\nEOFCONFIG",
                        Self::quote_path_for_shell(&config_path),
                        config
                    );
                    self.execute(server_id, &cmd).await?;
                    log::info!("[write_remote_live_config] Wrote Codex config.toml to {}", config_path);
                }
            }
            "gemini" => {
                // Gemini: Write .env file
                let gemini_dir = crate::server_settings::get_server_gemini_config_dir(server_id)
                    .unwrap_or_else(|| "~/.gemini".to_string());
                // settings_config should contain the env content as a string or structured data
                let env_content = if let Some(s) = settings_config.as_str() {
                    s.to_string()
                } else if let Some(obj) = settings_config.as_object() {
                    // Convert object to env format
                    obj.iter()
                        .filter_map(|(k, v)| v.as_str().map(|val| format!("{}={}", k, val)))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    return Err(SshError::InvalidConfig("Gemini config format not recognized".to_string()));
                };

                let mkdir_cmd = format!("mkdir -p {}", Self::quote_path_for_shell(&gemini_dir));
                self.execute(server_id, &mkdir_cmd).await?;

                let env_path = format!("{}/.env", gemini_dir);
                let cmd = format!(
                    "cat > {} << 'EOFCONFIG'\n{}\nEOFCONFIG",
                    Self::quote_path_for_shell(&env_path),
                    env_content
                );
                self.execute(server_id, &cmd).await?;
                log::info!("[write_remote_live_config] Wrote Gemini .env to {}", env_path);
            }
            _ => {
                log::warn!("[write_remote_live_config] Unknown app_type: {}", app_type);
            }
        }

        Ok(())
    }

    async fn remote_file_exists(&self, server_id: &str, path: &str) -> bool {
        let quoted_path = Self::quote_path_for_shell(path);
        let check_cmd = format!("test -f {} && echo 'exists'", quoted_path);
        self.execute(server_id, &check_cmd)
            .await
            .ok()
            .is_some_and(|out| out.trim() == "exists")
    }

    /// 读取远程服务器上的 Live 配置文件内容（Claude/Codex/Gemini）
    ///
    /// 返回结构与本地 `read_live_provider_settings` 一致：
    /// - claude: settings.json (or claude.json)
    /// - codex: { auth: <json>, config: <toml text> }
    /// - gemini: { env: <object>, config: <object> }
    pub async fn read_remote_live_settings(
        &self,
        server_id: &str,
        app_type: &str,
    ) -> Result<serde_json::Value, SshError> {
        match app_type {
            "claude" => {
                let claude_dir = crate::server_settings::get_server_claude_config_dir(server_id)
                    .unwrap_or_else(|| "~/.claude".to_string());

                let settings_path = format!("{}/settings.json", claude_dir);
                let legacy_path = format!("{}/claude.json", claude_dir);
                let target_path = if self.remote_file_exists(server_id, &settings_path).await {
                    settings_path
                } else if self.remote_file_exists(server_id, &legacy_path).await {
                    legacy_path
                } else {
                    return Err(SshError::FileReadFailed(
                        "Claude settings file is missing".to_string(),
                    ));
                };

                let quoted_path = Self::quote_path_for_shell(&target_path);
                let content = self
                    .execute(server_id, &format!("cat {}", quoted_path))
                    .await?;
                let value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
                    SshError::FileReadFailed(format!("Failed to parse Claude settings.json: {e}"))
                })?;
                Ok(value)
            }
            "codex" => {
                let codex_dir = crate::server_settings::get_server_codex_config_dir(server_id)
                    .unwrap_or_else(|| "~/.codex".to_string());

                let auth_path = format!("{}/auth.json", codex_dir);
                if !self.remote_file_exists(server_id, &auth_path).await {
                    return Err(SshError::FileReadFailed(
                        "Codex configuration missing: auth.json not found".to_string(),
                    ));
                }

                let quoted_auth_path = Self::quote_path_for_shell(&auth_path);
                let auth_text = self
                    .execute(server_id, &format!("cat {}", quoted_auth_path))
                    .await?;

                let auth_text = auth_text.strip_prefix('\u{feff}').unwrap_or(&auth_text);
                let auth: serde_json::Value = serde_json::from_str(auth_text).map_err(|e| {
                    SshError::FileReadFailed(format!("Failed to parse Codex auth.json: {e}"))
                })?;

                let config_path = format!("{}/config.toml", codex_dir);
                let config_text = if self.remote_file_exists(server_id, &config_path).await {
                    let quoted_config_path = Self::quote_path_for_shell(&config_path);
                    self.execute(server_id, &format!("cat {}", quoted_config_path))
                        .await
                        .unwrap_or_default()
                } else {
                    String::new()
                };

                Ok(serde_json::json!({ "auth": auth, "config": config_text }))
            }
            "gemini" => {
                let gemini_dir = crate::server_settings::get_server_gemini_config_dir(server_id)
                    .unwrap_or_else(|| "~/.gemini".to_string());

                let env_path = format!("{}/.env", gemini_dir);
                if !self.remote_file_exists(server_id, &env_path).await {
                    return Err(SshError::FileReadFailed(
                        "Gemini .env file not found".to_string(),
                    ));
                }
                let quoted_env_path = Self::quote_path_for_shell(&env_path);
                let env_text = self
                    .execute(server_id, &format!("cat {}", quoted_env_path))
                    .await?;
                let env_map = crate::gemini_config::parse_env_file(&env_text);
                let env_json = crate::gemini_config::env_to_json(&env_map);
                let env_obj = env_json
                    .get("env")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));

                let settings_path = format!("{}/settings.json", gemini_dir);
                let config_obj = if self.remote_file_exists(server_id, &settings_path).await {
                    let quoted_settings_path = Self::quote_path_for_shell(&settings_path);
                    let cfg_text = self
                        .execute(server_id, &format!("cat {}", quoted_settings_path))
                        .await?;
                    serde_json::from_str::<serde_json::Value>(&cfg_text).map_err(|e| {
                        SshError::FileReadFailed(format!(
                            "Failed to parse Gemini settings.json: {e}"
                        ))
                    })?
                } else {
                    serde_json::json!({})
                };

                Ok(serde_json::json!({ "env": env_obj, "config": config_obj }))
            }
            _ => Err(SshError::InvalidConfig(format!(
                "Unknown app_type: {}",
                app_type
            ))),
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

        let sqlite3_path = self.check_remote_sqlite3(server_id).await;
        let remote_db_path = self.resolve_db_path(server_id).await;
        let quoted_db_path = Self::quote_path_for_shell(&remote_db_path);

        if let Some(sqlite3) = sqlite3_path {
            let sql_escape = |s: &str| s.replace("'", "''");
            let sql = format!(
                "UPDATE providers SET is_proxy_target={} WHERE id='{}' AND app_type='{}'",
                if enabled { 1 } else { 0 },
                sql_escape(provider_id),
                app_type
            );
            self.execute(server_id, &format!("{} {} '{}'", sqlite3, quoted_db_path, sql.replace("'", "'\\''"))).await.map(|_| ())
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

    /// 启动 SSH 远程端口转发
    ///
    /// 这会创建一个 SSH 隧道，将本地服务器的端口转发到远程服务器
    /// 使用 ssh -R remote_port:local_host:local_port 命令
    pub async fn start_port_forwarding(
        &self,
        server_id: &str,
        local_address: &str,
        remote_port: u16,
    ) -> Result<PortForwardingStatus, SshError> {
        log::info!(
            "[start_port_forwarding] Starting port forwarding for server: {}, local: {}, remote port: {}",
            server_id,
            local_address,
            remote_port
        );

        // 检查是否已有转发进程在运行
        {
            let forwards = self.port_forwards.read().await;
            if forwards.contains_key(server_id) {
                log::warn!("[start_port_forwarding] Port forwarding already active for server: {}", server_id);
                // 返回当前状态
                let status = self.port_forward_status.read().await;
                if let Some(s) = status.get(server_id) {
                    return Ok(s.clone());
                }
            }
        }

        // 获取服务器配置
        let config = {
            let configs = self.configs.read().await;
            configs.get(server_id).cloned().ok_or(SshError::NotConnected)?
        };

        // 构建 SSH 命令
        // ssh -N -R remote_port:localhost:local_port user@host -p port
        let ssh_args = self.build_ssh_args(&config, local_address, remote_port)?;

        log::info!("[start_port_forwarding] SSH command args: {:?}", ssh_args);

        // 启动 SSH 进程
        let child = std::process::Command::new("ssh")
            .args(&ssh_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SshError::PortForwardingFailed(format!("Failed to start SSH process: {}", e)))?;

        // 等待一小段时间确认进程启动成功
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // 保存进程和状态
        let status = PortForwardingStatus {
            is_active: true,
            local_address: local_address.to_string(),
            remote_port,
        };

        {
            let mut forwards = self.port_forwards.write().await;
            forwards.insert(server_id.to_string(), child);
        }
        {
            let mut pf_status = self.port_forward_status.write().await;
            pf_status.insert(server_id.to_string(), status.clone());
        }

        log::info!("[start_port_forwarding] Port forwarding started successfully for server: {}", server_id);
        Ok(status)
    }

    /// 停止 SSH 端口转发
    pub async fn stop_port_forwarding(&self, server_id: &str) -> Result<(), SshError> {
        log::info!("[stop_port_forwarding] Stopping port forwarding for server: {}", server_id);

        // 获取并终止进程
        let mut child = {
            let mut forwards = self.port_forwards.write().await;
            forwards.remove(server_id)
        };

        if let Some(ref mut child) = child {
            // 尝试优雅终止
            let _ = child.kill();
            let _ = child.wait();
            log::info!("[stop_port_forwarding] SSH process killed for server: {}", server_id);
        }

        // 清除状态
        {
            let mut pf_status = self.port_forward_status.write().await;
            pf_status.remove(server_id);
        }

        Ok(())
    }

    /// 启动 SSH 远程端口转发到目标地址
    ///
    /// 这会创建一个 SSH 隧道，让远程服务器的 remote_port 转发到 target_address
    /// 使用 ssh -R remote_port:target_host:target_port 命令
    ///
    /// 例如：ssh -R 8080:api.anthropic.com:443 表示远程服务器的 8080 端口
    /// 会被转发到 api.anthropic.com:443
    pub async fn start_remote_port_forwarding_to_target(
        &self,
        server_id: &str,
        remote_port: u16,
        target_address: &str,
    ) -> Result<PortForwardingStatus, SshError> {
        log::info!(
            "[start_remote_port_forwarding_to_target] Starting for server: {}, remote_port: {}, target: {}",
            server_id,
            remote_port,
            target_address
        );

        // 检查是否已有转发进程在运行
        {
            let forwards = self.port_forwards.read().await;
            if forwards.contains_key(server_id) {
                log::warn!("[start_remote_port_forwarding_to_target] Port forwarding already active for server: {}", server_id);
                // 返回当前状态
                let status = self.port_forward_status.read().await;
                if let Some(s) = status.get(server_id) {
                    return Ok(s.clone());
                }
            }
        }

        // 获取服务器配置
        let config = {
            let configs = self.configs.read().await;
            configs.get(server_id).cloned().ok_or(SshError::NotConnected)?
        };

        // 构建 SSH 命令
        let ssh_args = self.build_ssh_args_for_target(&config, remote_port, target_address)?;

        log::info!("[start_remote_port_forwarding_to_target] SSH command args: {:?}", ssh_args);

        // 启动 SSH 进程
        let child = std::process::Command::new("ssh")
            .args(&ssh_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SshError::PortForwardingFailed(format!("Failed to start SSH process: {}", e)))?;

        // 等待一小段时间确认进程启动成功
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // 保存进程和状态
        let status = PortForwardingStatus {
            is_active: true,
            local_address: target_address.to_string(),
            remote_port,
        };

        {
            let mut forwards = self.port_forwards.write().await;
            forwards.insert(server_id.to_string(), child);
        }
        {
            let mut pf_status = self.port_forward_status.write().await;
            pf_status.insert(server_id.to_string(), status.clone());
        }

        log::info!("[start_remote_port_forwarding_to_target] Port forwarding started successfully for server: {}", server_id);
        Ok(status)
    }

    /// 构建 SSH 命令参数（转发到目标地址）
    fn build_ssh_args_for_target(
        &self,
        config: &SshConfig,
        remote_port: u16,
        target_address: &str,
    ) -> Result<Vec<String>, SshError> {
        let mut args = Vec::new();

        // -N: 不执行远程命令
        args.push("-N".to_string());

        // -o: SSH 选项
        args.push("-o".to_string());
        args.push("StrictHostKeyChecking=no".to_string());
        args.push("-o".to_string());
        args.push("UserKnownHostsFile=/dev/null".to_string());
        args.push("-o".to_string());
        args.push("ServerAliveInterval=30".to_string());
        args.push("-o".to_string());
        args.push("ServerAliveCountMax=3".to_string());
        args.push("-o".to_string());
        args.push("ExitOnForwardFailure=yes".to_string());

        // -R: 远程端口转发
        // 格式: remote_port:target_host:target_port
        // 让远程服务器监听 remote_port，转发到目标地址
        args.push("-R".to_string());
        args.push(format!("{}:{}", remote_port, target_address));

        // 私钥认证
        if let SshAuthType::Key = config.auth_type {
            if let Some(key_path) = &config.private_key_path {
                // 展开 ~
                let expanded_path = if key_path.starts_with("~/") {
                    if let Some(home) = dirs::home_dir() {
                        home.join(&key_path[2..]).to_string_lossy().to_string()
                    } else {
                        key_path.clone()
                    }
                } else {
                    key_path.clone()
                };
                args.push("-i".to_string());
                args.push(expanded_path);
            }
        }

        // 端口
        args.push("-p".to_string());
        args.push(config.port.to_string());

        // 用户名@主机
        args.push(format!("{}@{}", config.username, config.host));

        Ok(args)
    }

    /// 获取端口转发状态
    pub async fn get_port_forwarding_status(&self, server_id: &str) -> Option<PortForwardingStatus> {
        // 首先检查进程是否仍在运行
        let is_running = {
            let mut forwards = self.port_forwards.write().await;
            if let Some(child) = forwards.get_mut(server_id) {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        // 进程已退出
                        false
                    }
                    Ok(None) => {
                        // 进程仍在运行
                        true
                    }
                    Err(_) => false,
                }
            } else {
                false
            }
        };

        if !is_running {
            // 清理已退出的进程状态
            {
                let mut forwards = self.port_forwards.write().await;
                forwards.remove(server_id);
            }
            {
                let mut pf_status = self.port_forward_status.write().await;
                pf_status.remove(server_id);
            }
            return None;
        }

        let status = self.port_forward_status.read().await;
        status.get(server_id).cloned()
    }

    /// 构建 SSH 命令参数
    fn build_ssh_args(
        &self,
        config: &SshConfig,
        local_address: &str,
        remote_port: u16,
    ) -> Result<Vec<String>, SshError> {
        let mut args = Vec::new();

        // -N: 不执行远程命令
        args.push("-N".to_string());

        // -o: SSH 选项
        args.push("-o".to_string());
        args.push("StrictHostKeyChecking=no".to_string());
        args.push("-o".to_string());
        args.push("UserKnownHostsFile=/dev/null".to_string());
        args.push("-o".to_string());
        args.push("ServerAliveInterval=30".to_string());
        args.push("-o".to_string());
        args.push("ServerAliveCountMax=3".to_string());
        args.push("-o".to_string());
        args.push("ExitOnForwardFailure=yes".to_string());

        // -R: 远程端口转发
        // 格式: remote_port:local_host:local_port
        // 让远程服务器监听 remote_port，转发到本地的 local_address
        args.push("-R".to_string());
        args.push(format!("{}:{}", remote_port, local_address));

        // 私钥认证
        if let SshAuthType::Key = config.auth_type {
            if let Some(key_path) = &config.private_key_path {
                // 展开 ~
                let expanded_path = if key_path.starts_with("~/") {
                    if let Some(home) = dirs::home_dir() {
                        home.join(&key_path[2..]).to_string_lossy().to_string()
                    } else {
                        key_path.clone()
                    }
                } else {
                    key_path.clone()
                };
                args.push("-i".to_string());
                args.push(expanded_path);
            }
        }

        // 端口
        args.push("-p".to_string());
        args.push(config.port.to_string());

        // 用户名@主机
        args.push(format!("{}@{}", config.username, config.host));

        Ok(args)
    }
}

impl Default for SshService {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== RemoteProviderStore Implementation ====================
//
// This implements the ProviderStore trait for remote SSH-based provider management.
// It allows ProviderService to work transparently with remote servers.

use crate::database::ProviderStore;
use crate::error::AppError;
use crate::provider::Provider;
use indexmap::IndexMap;

/// Remote Provider Store implementation
///
/// Implements ProviderStore trait for remote SSH-connected servers.
/// Uses blocking async operations internally since the trait is sync.
pub struct RemoteProviderStore<'a> {
    ssh_service: &'a SshService,
    server_id: String,
}

impl<'a> RemoteProviderStore<'a> {
    pub fn new(ssh_service: &'a SshService, server_id: String) -> Self {
        Self {
            ssh_service,
            server_id,
        }
    }

    /// Get the sqlite3 path and db path for remote operations
    fn get_db_info(&self) -> Result<(Option<String>, String), AppError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| AppError::Message("No tokio runtime available".into()))?;

        // 使用 block_in_place 避免在 async 上下文中调用 block_on 导致 panic
        let (sqlite3_path, db_path) = tokio::task::block_in_place(|| {
            rt.block_on(async {
                let sqlite3_path = self.ssh_service.check_remote_sqlite3(&self.server_id).await;
                let db_path = self.ssh_service.resolve_db_path(&self.server_id).await;
                (sqlite3_path, db_path)
            })
        });

        Ok((sqlite3_path, db_path))
    }

    /// Execute SQL on remote database
    fn execute_sql(&self, sql: &str) -> Result<String, AppError> {
        let (sqlite3_path, db_path) = self.get_db_info()?;

        let sqlite3 = sqlite3_path.ok_or_else(|| {
            AppError::Message("Remote server does not have sqlite3 installed".into())
        })?;

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| AppError::Message("No tokio runtime available".into()))?;

        // Escape single quotes in SQL for shell
        let escaped_sql = sql.replace("'", "'\\''");
        let quoted_db_path = SshService::quote_path_for_shell(&db_path);
        let cmd = format!("{} {} '{}'", sqlite3, quoted_db_path, escaped_sql);

        tokio::task::block_in_place(|| {
            rt.block_on(self.ssh_service.execute(&self.server_id, &cmd))
        })
        .map_err(|e| AppError::Message(format!("SSH SQL execution failed: {}", e)))
    }

    /// SQL escape helper
    fn sql_escape(s: &str) -> String {
        s.replace("'", "''")
    }
}

impl ProviderStore for RemoteProviderStore<'_> {
    fn get_all_providers(&self, app_type: &str) -> Result<IndexMap<String, Provider>, AppError> {
        let (sqlite3_path, db_path) = self.get_db_info()?;

        let sqlite3 = match sqlite3_path {
            Some(p) => p,
            None => return Ok(IndexMap::new()), // No sqlite3, return empty
        };

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| AppError::Message("No tokio runtime available".into()))?;

        // Query all providers as JSON
        let quoted_db_path = SshService::quote_path_for_shell(&db_path);
        let query = format!(
            "{} {} \"SELECT json_group_array(json_object('id', id, 'name', name, 'appType', app_type, 'settingsConfig', settings_config, 'websiteUrl', website_url, 'category', category, 'createdAt', created_at, 'sortIndex', sort_index, 'notes', notes, 'icon', icon, 'iconColor', icon_color, 'meta', meta, 'isCurrent', is_current, 'isProxyTarget', is_proxy_target)) FROM providers WHERE app_type = '{}'\"",
            sqlite3, quoted_db_path, app_type
        );

        let result = tokio::task::block_in_place(|| {
            rt.block_on(self.ssh_service.execute(&self.server_id, &query))
        })
        .map_err(|e| AppError::Message(format!("Failed to query providers: {}", e)))?;

        // Parse JSON result
        let providers_json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|e| AppError::Message(format!("Failed to parse providers JSON: {}", e)))?;

        let mut providers = IndexMap::new();
        if let Some(arr) = providers_json.as_array() {
            for item in arr {
                if let Some(id) = item["id"].as_str() {
                    if let Ok(provider) = Provider::from_db_json(item, id.to_string()) {
                        providers.insert(id.to_string(), provider);
                    }
                }
            }
        }

        Ok(providers)
    }

    fn get_provider_by_id(&self, id: &str, app_type: &str) -> Result<Option<Provider>, AppError> {
        let providers = self.get_all_providers(app_type)?;
        Ok(providers.get(id).cloned())
    }

    fn save_provider(&self, app_type: &str, provider: &Provider) -> Result<(), AppError> {
        let (sqlite3_path, db_path) = self.get_db_info()?;

        let sqlite3 = sqlite3_path.ok_or_else(|| {
            AppError::Message("Remote server does not have sqlite3 installed".into())
        })?;

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| AppError::Message("No tokio runtime available".into()))?;

        // Ensure directory and table exist
        tokio::task::block_in_place(|| {
            rt.block_on(self.ssh_service.ensure_remote_dir(&self.server_id, &db_path))
        })
            .map_err(|e| AppError::Message(e.to_string()))?;

        // Create table if not exists
        let quoted_db_path = SshService::quote_path_for_shell(&db_path);
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
        let cmd = format!("{} {} \"{}\"", sqlite3, quoted_db_path, create_table_sql);
        tokio::task::block_in_place(|| {
            rt.block_on(self.ssh_service.execute(&self.server_id, &cmd))
        })
        .map_err(|e| AppError::Message(format!("Failed to create table: {}", e)))?;

        // Prepare values
        let settings_config_str = serde_json::to_string(&provider.settings_config).unwrap_or_default();
        let meta_str = provider
            .meta
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default())
            .unwrap_or_else(|| "{}".to_string());

        // Check if provider exists
        let check_sql = format!(
            "SELECT COUNT(*) FROM providers WHERE id='{}' AND app_type='{}'",
            Self::sql_escape(&provider.id),
            app_type
        );
        let check_cmd = format!("{} {} '{}'", sqlite3, quoted_db_path, check_sql.replace("'", "'\\''"));
        let count_str = tokio::task::block_in_place(|| {
            rt.block_on(self.ssh_service.execute(&self.server_id, &check_cmd))
        })
        .map_err(|e| AppError::Message(format!("Failed to check provider: {}", e)))?;
        let exists = count_str.trim().parse::<i32>().unwrap_or(0) > 0;

        if exists {
            // Update
            let sql = format!(
                "UPDATE providers SET name='{}', settings_config='{}', website_url={}, category={}, sort_index={}, notes={}, icon={}, icon_color={}, meta='{}' WHERE id='{}' AND app_type='{}'",
                Self::sql_escape(&provider.name),
                Self::sql_escape(&settings_config_str),
                provider.website_url.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.category.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.sort_index.map(|v| v.to_string()).unwrap_or_else(|| "NULL".to_string()),
                provider.notes.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.icon.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.icon_color.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                Self::sql_escape(&meta_str),
                Self::sql_escape(&provider.id),
                app_type
            );
            self.execute_sql(&sql)?;
        } else {
            // Insert
            let sql = format!(
                "INSERT INTO providers (id, app_type, name, settings_config, website_url, category, created_at, sort_index, notes, icon, icon_color, meta, is_current, is_proxy_target) VALUES ('{}', '{}', '{}', '{}', {}, {}, {}, {}, {}, {}, {}, '{}', 0, {})",
                Self::sql_escape(&provider.id),
                app_type,
                Self::sql_escape(&provider.name),
                Self::sql_escape(&settings_config_str),
                provider.website_url.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.category.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.created_at.map(|v| v.to_string()).unwrap_or_else(|| "NULL".to_string()),
                provider.sort_index.map(|v| v.to_string()).unwrap_or_else(|| "NULL".to_string()),
                provider.notes.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.icon.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                provider.icon_color.as_ref().map(|s| format!("'{}'", Self::sql_escape(s))).unwrap_or_else(|| "NULL".to_string()),
                Self::sql_escape(&meta_str),
                if provider.is_proxy_target.unwrap_or(false) { 1 } else { 0 }
            );
            self.execute_sql(&sql)?;
        }

        Ok(())
    }

    fn delete_provider(&self, app_type: &str, id: &str) -> Result<(), AppError> {
        let sql = format!(
            "DELETE FROM providers WHERE id='{}' AND app_type='{}'",
            Self::sql_escape(id),
            app_type
        );
        self.execute_sql(&sql)?;
        Ok(())
    }

    fn get_current_provider(&self, app_type: &str) -> Result<Option<String>, AppError> {
        let sql = format!(
            "SELECT id FROM providers WHERE app_type='{}' AND is_current=1 LIMIT 1",
            app_type
        );
        let result = self.execute_sql(&sql)?;
        let id = result.trim();
        if id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(id.to_string()))
        }
    }

    fn set_current_provider(&self, app_type: &str, id: &str) -> Result<(), AppError> {
        // Reset all to 0, then set the target to 1
        let sql = format!(
            "UPDATE providers SET is_current=0 WHERE app_type='{}'; UPDATE providers SET is_current=1 WHERE id='{}' AND app_type='{}'",
            app_type,
            Self::sql_escape(id),
            app_type
        );
        self.execute_sql(&sql)?;
        Ok(())
    }

    fn set_proxy_target_provider(&self, app_type: &str, id: &str) -> Result<(), AppError> {
        // Reset all to 0, then set the target to 1
        let sql = format!(
            "UPDATE providers SET is_proxy_target=0 WHERE app_type='{}'; UPDATE providers SET is_proxy_target=1 WHERE id='{}' AND app_type='{}'",
            app_type,
            Self::sql_escape(id),
            app_type
        );
        self.execute_sql(&sql)?;
        Ok(())
    }

    fn write_live_config(&self, app_type: &str, settings_config: &serde_json::Value) -> Result<(), AppError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| AppError::Message("No tokio runtime available".into()))?;

        tokio::task::block_in_place(|| {
            rt.block_on(
                self.ssh_service
                    .write_remote_live_config(&self.server_id, app_type, settings_config),
            )
        })
        .map_err(|e| AppError::Message(format!("Failed to write remote live config: {}", e)))
    }
}

// RemoteProviderStore is used internally and re-exported via services module if needed
#[allow(dead_code)]
pub use RemoteProviderStore as SshProviderStore;
