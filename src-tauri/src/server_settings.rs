//! 远程服务器设置存储模块
//!
//! 用于持久化存储远程服务器的工作目录等配置信息

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use tauri_plugin_store::StoreExt;

use crate::error::AppError;

/// 存储文件名
const STORE_FILE: &str = "server_settings.json";

/// 单个服务器的设置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServerSettings {
    /// 工作目录（远程数据库路径）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// 全局缓存：server_id -> ServerSettings
static SERVER_SETTINGS_CACHE: OnceLock<RwLock<HashMap<String, ServerSettings>>> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<String, ServerSettings>> {
    SERVER_SETTINGS_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// 从缓存中获取服务器设置
pub fn get_server_settings_cached(server_id: &str) -> Option<ServerSettings> {
    cache().read().ok()?.get(server_id).cloned()
}

/// 获取服务器的工作目录（从缓存）
pub fn get_server_working_dir(server_id: &str) -> Option<String> {
    get_server_settings_cached(server_id).and_then(|s| s.working_dir)
}

/// 从 Store 读取所有服务器设置
fn read_all_from_store(app: &tauri::AppHandle) -> HashMap<String, ServerSettings> {
    let store = match app.store_builder(STORE_FILE).build() {
        Ok(store) => store,
        Err(e) => {
            log::warn!("[server_settings] 无法创建 Store: {e}");
            return HashMap::new();
        }
    };

    let mut result = HashMap::new();

    // 遍历 store 中的所有键值对
    for (key, value) in store.entries() {
        if let Ok(settings) = serde_json::from_value::<ServerSettings>(value.clone()) {
            result.insert(key.clone(), settings);
        }
    }

    result
}

/// 从 Store 读取单个服务器的设置
fn read_from_store(app: &tauri::AppHandle, server_id: &str) -> Option<ServerSettings> {
    let store = match app.store_builder(STORE_FILE).build() {
        Ok(store) => store,
        Err(e) => {
            log::warn!("[server_settings] 无法创建 Store: {e}");
            return None;
        }
    };

    store.get(server_id).and_then(|v| {
        serde_json::from_value::<ServerSettings>(v.clone()).ok()
    })
}

/// 刷新缓存（从 Store 读取并更新缓存）
pub fn refresh_cache(app: &tauri::AppHandle) {
    let settings = read_all_from_store(app);
    if let Ok(mut guard) = cache().write() {
        *guard = settings;
    }
    log::info!("[server_settings] 缓存已刷新");
}

/// 保存服务器设置到 Store 并更新缓存
pub fn save_server_settings(
    app: &tauri::AppHandle,
    server_id: &str,
    settings: ServerSettings,
) -> Result<(), AppError> {
    let store = app
        .store_builder(STORE_FILE)
        .build()
        .map_err(|e| AppError::Message(format!("创建 Store 失败: {e}")))?;

    let value = serde_json::to_value(&settings)
        .map_err(|e| AppError::Message(format!("序列化设置失败: {e}")))?;

    store.set(server_id.to_string(), value);

    store
        .save()
        .map_err(|e| AppError::Message(format!("保存 Store 失败: {e}")))?;

    // 更新缓存
    if let Ok(mut guard) = cache().write() {
        guard.insert(server_id.to_string(), settings.clone());
    }

    log::info!(
        "[server_settings] 已保存服务器 {} 的设置: {:?}",
        server_id,
        settings
    );

    Ok(())
}

/// 获取服务器设置（优先从缓存，缓存未命中则从 Store 读取）
pub fn get_server_settings(app: &tauri::AppHandle, server_id: &str) -> ServerSettings {
    // 先尝试从缓存获取
    if let Some(settings) = get_server_settings_cached(server_id) {
        return settings;
    }

    // 缓存未命中，从 Store 读取
    if let Some(settings) = read_from_store(app, server_id) {
        // 更新缓存
        if let Ok(mut guard) = cache().write() {
            guard.insert(server_id.to_string(), settings.clone());
        }
        return settings;
    }

    // 返回默认值
    ServerSettings::default()
}

/// 删除服务器设置
pub fn delete_server_settings(app: &tauri::AppHandle, server_id: &str) -> Result<(), AppError> {
    let store = app
        .store_builder(STORE_FILE)
        .build()
        .map_err(|e| AppError::Message(format!("创建 Store 失败: {e}")))?;

    store.delete(server_id);

    store
        .save()
        .map_err(|e| AppError::Message(format!("保存 Store 失败: {e}")))?;

    // 更新缓存
    if let Ok(mut guard) = cache().write() {
        guard.remove(server_id);
    }

    log::info!("[server_settings] 已删除服务器 {} 的设置", server_id);

    Ok(())
}
