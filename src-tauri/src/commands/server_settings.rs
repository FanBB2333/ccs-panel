//! 服务器设置相关的 Tauri 命令

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::server_settings;

/// 服务器设置请求
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSettingsRequest {
    /// 工作目录（远程数据库路径）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Claude 配置目录
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_config_dir: Option<String>,
    /// Codex 配置目录
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex_config_dir: Option<String>,
    /// Gemini 配置目录
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_config_dir: Option<String>,
}

/// 服务器设置响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSettingsResponse {
    /// 工作目录（远程数据库路径）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Claude 配置目录
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_config_dir: Option<String>,
    /// Codex 配置目录
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex_config_dir: Option<String>,
    /// Gemini 配置目录
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gemini_config_dir: Option<String>,
}

/// 保存服务器设置
#[tauri::command]
pub async fn save_server_settings(
    app: AppHandle,
    server_id: String,
    settings: ServerSettingsRequest,
) -> Result<(), String> {
    let server_settings = server_settings::ServerSettings {
        working_dir: settings.working_dir,
        claude_config_dir: settings.claude_config_dir,
        codex_config_dir: settings.codex_config_dir,
        gemini_config_dir: settings.gemini_config_dir,
    };

    server_settings::save_server_settings(&app, &server_id, server_settings)
        .map_err(|e| e.to_string())
}

/// 获取服务器设置
#[tauri::command]
pub async fn get_server_settings(
    app: AppHandle,
    server_id: String,
) -> Result<ServerSettingsResponse, String> {
    let settings = server_settings::get_server_settings(&app, &server_id);

    Ok(ServerSettingsResponse {
        working_dir: settings.working_dir,
        claude_config_dir: settings.claude_config_dir,
        codex_config_dir: settings.codex_config_dir,
        gemini_config_dir: settings.gemini_config_dir,
    })
}

/// 删除服务器设置
#[tauri::command]
pub async fn delete_server_settings(
    app: AppHandle,
    server_id: String,
) -> Result<(), String> {
    server_settings::delete_server_settings(&app, &server_id)
        .map_err(|e| e.to_string())
}
