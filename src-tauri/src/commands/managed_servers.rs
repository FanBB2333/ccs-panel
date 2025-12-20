//! 服务器面板：服务器列表持久化（统一存储，避免 dev/prod origin 导致 localStorage 不一致）

use crate::managed_servers::{load_managed_servers, save_managed_servers, ManagedServersMap};

/// 读取服务器列表（来源：`~/.cc-switch/servers.json` + `~/.cc-switch/servers.db`）
#[tauri::command]
pub async fn get_managed_servers() -> Result<ManagedServersMap, String> {
    load_managed_servers().map_err(|e| e.to_string())
}

/// 保存服务器列表（写入 `servers.json`，并将 password/passphrase 写入 `servers.db`）
#[tauri::command]
pub async fn set_managed_servers(servers: ManagedServersMap) -> Result<(), String> {
    save_managed_servers(servers).map_err(|e| e.to_string())
}

