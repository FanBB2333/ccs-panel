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

    /// 读取远程 CCS Panel 配置
    /// 尝试从远程服务器的 SQLite 数据库读取供应商配置
    pub async fn read_remote_config(
        &self,
        server_id: &str,
        app_type: &str,
    ) -> Result<RemoteConfig, SshError> {
        // 首先尝试找到远程的数据库路径
        // 默认路径: ~/.config/cc-switch/cc-switch.db 或 ~/Library/Application Support/cc-switch/cc-switch.db
        let db_paths = vec![
            "~/.config/cc-switch/cc-switch.db",
            "~/Library/Application\\ Support/cc-switch/cc-switch.db",
            "~/.local/share/cc-switch/cc-switch.db",
        ];

        // 检查哪个路径存在
        let mut db_path = None;
        for path in &db_paths {
            let check_cmd = format!("test -f {} && echo 'exists' || echo 'not found'", path);
            if let Ok(result) = self.execute(server_id, &check_cmd).await {
                if result.trim() == "exists" {
                    db_path = Some(path.to_string());
                    break;
                }
            }
        }

        let db_path = db_path.ok_or_else(|| {
            SshError::FileReadFailed("Could not find cc-switch database on remote server".to_string())
        })?;

        // 使用 sqlite3 命令行工具读取供应商数据
        let query = format!(
            "sqlite3 {} \"SELECT json_group_array(json_object('id', id, 'name', name, 'app_type', app_type, 'settings_config', settings_config, 'category', category, 'website_url', website_url, 'icon', icon, 'icon_color', icon_color, 'sort_index', sort_index, 'is_current', is_current, 'created_at', created_at, 'updated_at', updated_at)) FROM providers WHERE app_type = '{}'\"",
            db_path, app_type
        );

        let providers_json = self.execute(server_id, &query).await?;

        // 解析 JSON
        let providers: serde_json::Value = serde_json::from_str(&providers_json).map_err(|e| {
            SshError::FileReadFailed(format!("Failed to parse providers JSON: {}", e))
        })?;

        // 查找当前供应商
        let current_query = format!(
            "sqlite3 {} \"SELECT id FROM providers WHERE app_type = '{}' AND is_current = 1 LIMIT 1\"",
            db_path, app_type
        );
        let current_id = self.execute(server_id, &current_query).await.ok();

        Ok(RemoteConfig {
            providers,
            current_provider_id: current_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        })
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
