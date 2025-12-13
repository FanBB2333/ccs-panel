//! SSH 相关的 Tauri 命令

use crate::services::ssh::{ConnectionStatus, PortForwardingStatus, RemoteConfig, SshConfig, SshError};
use crate::store::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;

/// SSH 连接请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConnectRequest {
    pub server_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub passphrase: Option<String>,
    /// 远程 sqlite3 可执行文件路径（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite3_path: Option<String>,
}

impl From<&SshConnectRequest> for SshConfig {
    fn from(req: &SshConnectRequest) -> Self {
        SshConfig {
            host: req.host.clone(),
            port: req.port,
            username: req.username.clone(),
            auth_type: if req.auth_type == "key" {
                crate::services::ssh::SshAuthType::Key
            } else {
                crate::services::ssh::SshAuthType::Password
            },
            password: req.password.clone(),
            private_key_path: req.private_key_path.clone(),
            passphrase: req.passphrase.clone(),
            sqlite3_path: req.sqlite3_path.clone(),
        }
    }
}

/// SSH 连接状态响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshStatusResponse {
    pub server_id: String,
    pub status: String,
}

fn ssh_error_to_string(e: SshError) -> String {
    e.to_string()
}

/// 连接到远程服务器
#[tauri::command]
pub async fn ssh_connect(
    state: State<'_, AppState>,
    request: SshConnectRequest,
) -> Result<SshStatusResponse, String> {
    let config = SshConfig::from(&request);

    state
        .ssh_service
        .connect(&request.server_id, &config)
        .await
        .map_err(ssh_error_to_string)?;

    Ok(SshStatusResponse {
        server_id: request.server_id,
        status: "connected".to_string(),
    })
}

/// 断开远程服务器连接
#[tauri::command]
pub async fn ssh_disconnect(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<SshStatusResponse, String> {
    state.ssh_service.disconnect(&server_id).await;

    Ok(SshStatusResponse {
        server_id,
        status: "disconnected".to_string(),
    })
}

/// 获取连接状态
#[tauri::command]
pub async fn ssh_get_status(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<SshStatusResponse, String> {
    let status = state.ssh_service.get_status(&server_id).await;

    let status_str = match status {
        ConnectionStatus::Connected => "connected",
        ConnectionStatus::Disconnected => "disconnected",
        ConnectionStatus::Connecting => "connecting",
        ConnectionStatus::Error => "error",
    };

    Ok(SshStatusResponse {
        server_id,
        status: status_str.to_string(),
    })
}

/// 测试 SSH 连接
#[tauri::command]
pub async fn ssh_test_connection(
    state: State<'_, AppState>,
    request: SshConnectRequest,
) -> Result<bool, String> {
    let config = SshConfig::from(&request);

    state
        .ssh_service
        .test_connection(&config)
        .await
        .map_err(ssh_error_to_string)?;

    Ok(true)
}

/// 读取远程配置
#[tauri::command]
pub async fn ssh_read_remote_config(
    state: State<'_, AppState>,
    server_id: String,
    app_type: String,
) -> Result<RemoteConfig, String> {
    state
        .ssh_service
        .read_remote_config(&server_id, &app_type)
        .await
        .map_err(ssh_error_to_string)
}

/// 在远程服务器执行命令
#[tauri::command]
pub async fn ssh_execute(
    state: State<'_, AppState>,
    server_id: String,
    command: String,
) -> Result<String, String> {
    state
        .ssh_service
        .execute(&server_id, &command)
        .await
        .map_err(ssh_error_to_string)
}

/// 添加远程供应商
#[tauri::command]
pub async fn ssh_add_remote_provider(
    state: State<'_, AppState>,
    server_id: String,
    provider: serde_json::Value,
    app_type: String,
) -> Result<(), String> {
    state
        .ssh_service
        .add_remote_provider(&server_id, &provider, &app_type)
        .await
        .map_err(ssh_error_to_string)
}

/// 更新远程供应商
#[tauri::command]
pub async fn ssh_update_remote_provider(
    state: State<'_, AppState>,
    server_id: String,
    provider: serde_json::Value,
    app_type: String,
) -> Result<(), String> {
    state
        .ssh_service
        .update_remote_provider(&server_id, &provider, &app_type)
        .await
        .map_err(ssh_error_to_string)
}

/// 切换远程供应商（设置当前供应商）
#[tauri::command]
pub async fn ssh_switch_remote_provider(
    state: State<'_, AppState>,
    server_id: String,
    provider_id: String,
    app_type: String,
) -> Result<(), String> {
    state
        .ssh_service
        .set_remote_current_provider(&server_id, &provider_id, &app_type)
        .await
        .map_err(ssh_error_to_string)
}

/// 删除远程供应商
#[tauri::command]
pub async fn ssh_delete_remote_provider(
    state: State<'_, AppState>,
    server_id: String,
    provider_id: String,
    app_type: String,
) -> Result<(), String> {
    state
        .ssh_service
        .delete_remote_provider(&server_id, &provider_id, &app_type)
        .await
        .map_err(ssh_error_to_string)
}

/// 启动 SSH 端口转发
#[tauri::command]
pub async fn ssh_start_port_forwarding(
    state: State<'_, AppState>,
    server_id: String,
    local_address: String,
    remote_port: u16,
) -> Result<PortForwardingStatus, String> {
    state
        .ssh_service
        .start_port_forwarding(&server_id, &local_address, remote_port)
        .await
        .map_err(ssh_error_to_string)
}

/// 停止 SSH 端口转发
#[tauri::command]
pub async fn ssh_stop_port_forwarding(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<(), String> {
    state
        .ssh_service
        .stop_port_forwarding(&server_id)
        .await
        .map_err(ssh_error_to_string)
}

/// 获取 SSH 端口转发状态
#[tauri::command]
pub async fn ssh_get_port_forwarding_status(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Option<PortForwardingStatus>, String> {
    Ok(state
        .ssh_service
        .get_port_forwarding_status(&server_id)
        .await)
}
