//! 代理服务业务逻辑层
//!
//! 提供代理服务器的启动、停止和配置管理

use crate::app_config::AppType;
use crate::config::{get_claude_settings_path, read_json_file, write_json_file};
use crate::database::Database;
use crate::proxy::server::ProxyServer;
use crate::proxy::types::*;
use crate::services::ssh::SshService;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ProxyService {
    db: Arc<Database>,
    server: Arc<RwLock<Option<ProxyServer>>>,
    ssh_service: Option<Arc<SshService>>,
    /// 当前代理服务的服务器ID（None表示本地，Some表示远程）
    current_server_id: Arc<RwLock<Option<String>>>,
    /// SSH端口转发的本地端口（动态分配）
    ssh_forward_port: Arc<RwLock<Option<u16>>>,
}

impl ProxyService {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            server: Arc::new(RwLock::new(None)),
            ssh_service: None,
            current_server_id: Arc::new(RwLock::new(None)),
            ssh_forward_port: Arc::new(RwLock::new(None)),
        }
    }

    /// 设置SSH服务引用（用于远程服务器代理）
    pub fn with_ssh_service(mut self, ssh_service: Arc<SshService>) -> Self {
        self.ssh_service = Some(ssh_service);
        self
    }

    /// 查找一个可用的本地端口
    async fn find_available_port() -> Result<u16, String> {
        use std::net::TcpListener;

        // 尝试绑定端口0，系统会自动分配一个可用端口
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| format!("无法分配端口: {}", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("无法获取分配的端口: {}", e))?
            .port();
        drop(listener);
        Ok(port)
    }

    /// 启动代理服务器
    pub async fn start(&self) -> Result<ProxyServerInfo, String> {
        // 1. 获取配置
        let mut config = self
            .db
            .get_proxy_config()
            .await
            .map_err(|e| format!("获取代理配置失败: {e}"))?;

        // 2. 确保配置启用（用户通过UI启动即表示希望启用）
        config.enabled = true;

        // 3. 检查是否已在运行
        if self.server.read().await.is_some() {
            return Err("代理服务已在运行中".to_string());
        }

        // 4. 创建并启动服务器
        let server = ProxyServer::new(config.clone(), self.db.clone());
        let info = server
            .start()
            .await
            .map_err(|e| format!("启动代理服务器失败: {e}"))?;

        // 5. 保存服务器实例
        *self.server.write().await = Some(server);

        // 6. 持久化 enabled 状态
        self.db
            .update_proxy_config(config)
            .await
            .map_err(|e| format!("保存代理配置失败: {e}"))?;

        log::info!("代理服务器已启动: {}:{}", info.address, info.port);
        Ok(info)
    }

    /// 启动代理服务器（带 Live 配置接管）
    pub async fn start_with_takeover(&self) -> Result<ProxyServerInfo, String> {
        // 1. 自动将各应用当前选中的供应商设置为代理目标
        self.setup_proxy_targets().await?;

        // 2. 备份各应用的 Live 配置
        self.backup_live_configs().await?;

        // 3. 同步 Live 配置中的 Token 到数据库（确保代理能读到最新的 Token）
        self.sync_live_to_providers().await?;

        // 4. 接管各应用的 Live 配置（写入代理地址，清空 Token）
        self.takeover_live_configs().await?;

        // 5. 设置接管状态
        self.db
            .set_live_takeover_active(true)
            .await
            .map_err(|e| format!("设置接管状态失败: {e}"))?;

        // 6. 启动代理服务器
        match self.start().await {
            Ok(info) => Ok(info),
            Err(e) => {
                // 启动失败，恢复原始配置
                log::error!("代理启动失败，尝试恢复原始配置: {e}");
                let _ = self.restore_live_configs().await;
                let _ = self.db.set_live_takeover_active(false).await;
                Err(e)
            }
        }
    }

    /// 启动代理服务器（带远程服务器支持）
    ///
    /// 如果提供了server_id，会为远程服务器启动SSH端口转发
    ///
    /// 简化版实现：
    /// 1. 获取当前选中的 Provider 的 ANTHROPIC_BASE_URL
    /// 2. 解析 URL 获取 host:port
    /// 3. 直接执行 ssh -R remote_port:api_host:api_port 转发
    /// 4. 修改远程配置文件指向 127.0.0.1:remote_port
    pub async fn start_with_takeover_for_server(
        &self,
        server_id: Option<String>,
    ) -> Result<ProxyServerInfo, String> {
        // 保存当前服务器ID
        {
            let mut current_id = self.current_server_id.write().await;
            *current_id = server_id.clone();
        }

        // 如果是远程服务器，需要SSH服务支持

        if let Some(ref sid) = server_id {
            let ssh_service = self
                .ssh_service
                .as_ref()
                .ok_or_else(|| "远程服务器代理需要SSH服务支持".to_string())?;

            log::info!("[ProxyService] 为远程服务器 {} 启动 SSH 转发代理", sid);

            // 1. 获取当前选中的 Claude Provider
            let provider_id = self
                .db
                .get_current_provider("claude")
                .ok()
                .flatten()
                .ok_or_else(|| "未选中 Claude Provider".to_string())?;

            let provider = self
                .db
                .get_provider_by_id(&provider_id, "claude")
                .map_err(|e| format!("获取 Provider 失败: {}", e))?
                .ok_or_else(|| "Provider 不存在".to_string())?;

            // 2. 从 Provider 中提取 ANTHROPIC_BASE_URL
            let base_url = self.extract_base_url_from_provider(&provider)?;
            log::info!("[ProxyService] 提取到 ANTHROPIC_BASE_URL: {}", base_url);

            // 3. 解析 URL 获取 host:port
            let target_address = self.parse_url_to_host_port(&base_url)?;
            log::info!("[ProxyService] 解析目标地址: {}", target_address);

            // 4. 分配一个可用端口用于远程监听
            let remote_port = Self::find_available_port().await?;
            log::info!("[ProxyService] 分配远程转发端口: {}", remote_port);

            // 5. 启动 SSH 远程端口转发
            // ssh -R remote_port:api_host:api_port
            log::info!(
                "[ProxyService] 启动 SSH 转发: 远程:{} -> {}",
                remote_port,
                target_address
            );

            match ssh_service
                .start_remote_port_forwarding_to_target(sid, remote_port, &target_address)
                .await
            {
                Ok(status) => {
                    log::info!("[ProxyService] SSH端口转发已启动: {:?}", status);

                    // 保存转发端口
                    {
                        let mut port = self.ssh_forward_port.write().await;
                        *port = Some(remote_port);
                    }

                    // 设置接管状态
                    self.db
                        .set_live_takeover_active(true)
                        .await
                        .map_err(|e| format!("设置接管状态失败: {e}"))?;

                    // 6. 修改远程配置文件，指向转发的端口
                    // 根据原始 URL 的协议决定使用 http 还是 https
                    let is_https = base_url.starts_with("https://");
                    if let Err(e) = self
                        .update_remote_configs_for_direct_proxy(sid, remote_port, is_https)
                        .await
                    {
                        log::error!("[ProxyService] 更新远程配置失败: {}", e);
                        // 清理已启动的服务
                        let _ = ssh_service.stop_port_forwarding(sid).await;
                        let _ = self.db.set_live_takeover_active(false).await;
                        return Err(format!("更新远程配置失败: {}", e));
                    }

                    Ok(ProxyServerInfo {
                        address: "127.0.0.1".to_string(),
                        port: remote_port,
                        started_at: chrono::Utc::now().to_rfc3339(),
                    })
                }
                Err(e) => {
                    log::error!("[ProxyService] SSH端口转发启动失败: {}", e);
                    Err(format!("SSH端口转发启动失败: {}", e))
                }
            }
        } else {
            // 本地服务器，直接启动代理
            self.start_with_takeover().await
        }
    }

    /// 从 Provider 配置中提取 ANTHROPIC_BASE_URL
    fn extract_base_url_from_provider(
        &self,
        provider: &crate::provider::Provider,
    ) -> Result<String, String> {
        // 1. 从 env 中获取
        if let Some(env) = provider.settings_config.get("env") {
            if let Some(url) = env.get("ANTHROPIC_BASE_URL").and_then(|v| v.as_str()) {
                if !url.is_empty() {
                    return Ok(url.trim_end_matches('/').to_string());
                }
            }
        }

        // 2. 尝试直接获取 base_url
        if let Some(url) = provider
            .settings_config
            .get("base_url")
            .and_then(|v| v.as_str())
        {
            if !url.is_empty() {
                return Ok(url.trim_end_matches('/').to_string());
            }
        }

        // 3. 尝试 baseURL
        if let Some(url) = provider
            .settings_config
            .get("baseURL")
            .and_then(|v| v.as_str())
        {
            if !url.is_empty() {
                return Ok(url.trim_end_matches('/').to_string());
            }
        }

        // 4. 默认使用官方 API
        Ok("https://api.anthropic.com".to_string())
    }

    /// 解析 URL 为 host:port 格式
    fn parse_url_to_host_port(&self, url: &str) -> Result<String, String> {
        use url::Url;

        let parsed = Url::parse(url).map_err(|e| format!("无效的 URL: {}", e))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| "URL 缺少主机名".to_string())?;

        let port = parsed.port().unwrap_or_else(|| match parsed.scheme() {
            "https" => 443,
            "http" => 80,
            _ => 443,
        });

        Ok(format!("{}:{}", host, port))
    }

    /// 更新远程服务器的配置文件（直接转发模式）
    ///
    /// 将 ANTHROPIC_BASE_URL 修改为指向 SSH 隧道端口
    async fn update_remote_configs_for_direct_proxy(
        &self,
        server_id: &str,
        forward_port: u16,
        _is_https: bool,
    ) -> Result<(), String> {
        let ssh_service = self
            .ssh_service
            .as_ref()
            .ok_or_else(|| "SSH服务未初始化".to_string())?;

        // 注意：SSH -R 转发的是 TCP 连接，远程访问时使用 http://127.0.0.1:port
        // 即使目标是 HTTPS，通过隧道后在远程端仍然是明文 HTTP
        // 因为 TLS 握手发生在隧道的另一端（目标服务器）
        let proxy_url = format!("http://127.0.0.1:{}", forward_port);

        log::info!("[ProxyService] 更新远程配置文件，指向 {}", proxy_url);

        // 只更新 Claude 配置
        let update_script = format!(
            r#"
            mkdir -p ~/.claude
            SETTINGS=~/.claude/settings.json
            if [ -f "$SETTINGS" ]; then
                # 备份原始文件（如果还没有备份）
                [ ! -f "$SETTINGS.proxy_backup" ] && cp "$SETTINGS" "$SETTINGS.proxy_backup"
                # 使用jq更新ANTHROPIC_BASE_URL
                if command -v jq >/dev/null 2>&1; then
                    jq '.env.ANTHROPIC_BASE_URL = "{}"' "$SETTINGS" > "$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS"
                    echo "updated_with_jq"
                else
                    # 如果没有jq，使用Python
                    if command -v python3 >/dev/null 2>&1; then
                        python3 -c "
import json
with open('$SETTINGS', 'r') as f:
    data = json.load(f)
if 'env' not in data:
    data['env'] = {{}}
data['env']['ANTHROPIC_BASE_URL'] = '{}'
with open('$SETTINGS', 'w') as f:
    json.dump(data, f, indent=2)
print('updated_with_python')
"
                    else
                        echo "no_json_tool"
                    fi
                fi
            else
                # 创建新配置文件
                echo '{{"env":{{"ANTHROPIC_BASE_URL":"{}"}}}}' > "$SETTINGS"
                echo "created_new"
            fi
        "#,
            proxy_url, proxy_url, proxy_url
        );

        match ssh_service.execute(server_id, &update_script).await {
            Ok(result) => {
                log::info!("[ProxyService] 更新远程 Claude 配置结果: {}", result.trim());
                Ok(())
            }
            Err(e) => {
                log::error!("[ProxyService] 更新远程 Claude 配置失败: {}", e);
                Err(format!("更新远程配置失败: {}", e))
            }
        }
    }

    /// 停止代理服务器（带远程服务器支持）
    pub async fn stop_with_restore_for_server(&self) -> Result<(), String> {
        // 获取当前服务器ID
        let server_id = {
            let current_id = self.current_server_id.read().await;
            current_id.clone()
        };

        if let Some(ref sid) = server_id {
            let ssh_service = self
                .ssh_service
                .as_ref()
                .ok_or_else(|| "远程服务器代理需要SSH服务支持".to_string())?;

            log::info!("[ProxyService] 停止远程服务器 {} 的代理", sid);

            // 1. 恢复远程配置文件
            if let Err(e) = self.restore_remote_configs(sid).await {
                log::warn!("[ProxyService] 恢复远程配置失败: {}", e);
            }

            // 2. 停止SSH端口转发
            if let Err(e) = ssh_service.stop_port_forwarding(sid).await {
                log::warn!("[ProxyService] 停止SSH端口转发失败: {}", e);
            }

            // 清除转发端口记录
            {
                let mut port = self.ssh_forward_port.write().await;
                *port = None;
            }

            // 3. 清除接管状态（远程模式不需要停止本地代理服务）
            self.db
                .set_live_takeover_active(false)
                .await
                .map_err(|e| format!("清除接管状态失败: {e}"))?;

            // 清除服务器ID
            {
                let mut current_id = self.current_server_id.write().await;
                *current_id = None;
            }

            log::info!("[ProxyService] 远程代理已停止，配置已恢复");
            Ok(())
        } else {
            // 本地服务器，直接停止
            self.stop_with_restore().await
        }
    }

    /// 更新远程服务器的配置文件，指向SSH转发的端口
    async fn update_remote_configs_for_proxy(
        &self,
        server_id: &str,
        forward_port: u16,
    ) -> Result<(), String> {
        let ssh_service = self
            .ssh_service
            .as_ref()
            .ok_or_else(|| "SSH服务未初始化".to_string())?;

        log::info!(
            "[ProxyService] 更新远程配置文件，指向127.0.0.1:{}",
            forward_port
        );

        let proxy_url = format!("http://127.0.0.1:{}", forward_port);
        let app_types = ["claude", "codex", "gemini"];

        for app_type in app_types {
            let update_script = match app_type {
                "claude" => {
                    // 更新 ~/.claude/settings.json
                    format!(
                        r#"
                        mkdir -p ~/.claude
                        SETTINGS=~/.claude/settings.json
                        if [ -f "$SETTINGS" ]; then
                            # 备份原始文件（如果还没有备份）
                            [ ! -f "$SETTINGS.proxy_backup" ] && cp "$SETTINGS" "$SETTINGS.proxy_backup"
                            # 使用jq更新ANTHROPIC_BASE_URL
                            if command -v jq >/dev/null 2>&1; then
                                jq '.env.ANTHROPIC_BASE_URL = "{}"' "$SETTINGS" > "$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS"
                            else
                                # 如果没有jq，使用sed（不太安全但是fallback方案）
                                echo '{{\"env\":{{\"ANTHROPIC_BASE_URL\":\"{}\"}}}}' > "$SETTINGS"
                            fi
                        fi
                    "#,
                        proxy_url, proxy_url
                    )
                }
                "codex" => {
                    // 更新 ~/.codex/auth.json
                    format!(
                        r#"
                        mkdir -p ~/.codex
                        AUTH=~/.codex/auth.json
                        if [ -f "$AUTH" ]; then
                            [ ! -f "$AUTH.proxy_backup" ] && cp "$AUTH" "$AUTH.proxy_backup"
                            if command -v jq >/dev/null 2>&1; then
                                jq '.OPENAI_BASE_URL = "{}"' "$AUTH" > "$AUTH.tmp" && mv "$AUTH.tmp" "$AUTH"
                            fi
                        fi
                    "#,
                        proxy_url
                    )
                }
                "gemini" => {
                    // 更新 ~/.gemini/.env
                    format!(
                        r#"
                        mkdir -p ~/.gemini
                        ENV=~/.gemini/.env
                        if [ -f "$ENV" ]; then
                            [ ! -f "$ENV.proxy_backup" ] && cp "$ENV" "$ENV.proxy_backup"
                            if grep -q "GEMINI_API_BASE=" "$ENV"; then
                                sed -i.bak 's|GEMINI_API_BASE=.*|GEMINI_API_BASE={}|' "$ENV"
                            else
                                echo "GEMINI_API_BASE={}" >> "$ENV"
                            fi
                        fi
                    "#,
                        proxy_url, proxy_url
                    )
                }
                _ => continue,
            };

            if let Err(e) = ssh_service.execute(server_id, &update_script).await {
                log::warn!("[ProxyService] 更新 {} 远程配置失败: {}", app_type, e);
            } else {
                log::info!("[ProxyService] 已更新 {} 远程配置", app_type);
            }
        }

        Ok(())
    }

    /// 恢复远程服务器的配置文件
    async fn restore_remote_configs(&self, server_id: &str) -> Result<(), String> {
        let ssh_service = self
            .ssh_service
            .as_ref()
            .ok_or_else(|| "SSH服务未初始化".to_string())?;

        log::info!("[ProxyService] 恢复远程配置文件");

        let app_types = ["claude", "codex", "gemini"];

        for app_type in app_types {
            let restore_script = match app_type {
                "claude" => r#"
                        SETTINGS=~/.claude/settings.json
                        if [ -f "$SETTINGS.proxy_backup" ]; then
                            mv "$SETTINGS.proxy_backup" "$SETTINGS"
                            echo "restored"
                        fi
                    "#
                .to_string(),
                "codex" => r#"
                        AUTH=~/.codex/auth.json
                        if [ -f "$AUTH.proxy_backup" ]; then
                            mv "$AUTH.proxy_backup" "$AUTH"
                            echo "restored"
                        fi
                    "#
                .to_string(),
                "gemini" => r#"
                        ENV=~/.gemini/.env
                        if [ -f "$ENV.proxy_backup" ]; then
                            mv "$ENV.proxy_backup" "$ENV"
                            echo "restored"
                        fi
                    "#
                .to_string(),
                _ => continue,
            };

            if let Err(e) = ssh_service.execute(server_id, &restore_script).await {
                log::warn!("[ProxyService] 恢复 {} 远程配置失败: {}", app_type, e);
            } else {
                log::info!("[ProxyService] 已恢复 {} 远程配置", app_type);
            }
        }

        Ok(())
    }

    /// 自动设置代理目标：将各应用当前选中的供应商设置为代理目标
    async fn setup_proxy_targets(&self) -> Result<(), String> {
        let app_types = ["claude", "codex", "gemini"];

        for app_type in app_types {
            // 获取当前选中的供应商
            if let Ok(Some(provider_id)) = self.db.get_current_provider(app_type) {
                // 设置为代理目标
                if let Err(e) = self.db.set_proxy_target(&provider_id, app_type, true).await {
                    log::warn!("设置 {} 的代理目标 {} 失败: {}", app_type, provider_id, e);
                } else {
                    log::info!(
                        "已将 {} 的当前供应商 {} 设置为代理目标",
                        app_type,
                        provider_id
                    );
                }
            } else {
                log::debug!("{} 没有当前供应商，跳过代理目标设置", app_type);
            }
        }

        Ok(())
    }

    /// 同步 Live 配置中的 Token 到数据库
    ///
    /// 在清空 Live Token 之前调用，确保数据库中的 Provider 配置有最新的 Token。
    /// 这样代理才能从数据库读取到正确的认证信息。
    async fn sync_live_to_providers(&self) -> Result<(), String> {
        // Claude: 同步 ANTHROPIC_AUTH_TOKEN
        if let Ok(live_config) = self.read_claude_live() {
            if let Some(provider_id) = self.db.get_current_provider("claude").ok().flatten() {
                if let Ok(Some(mut provider)) = self.db.get_provider_by_id(&provider_id, "claude") {
                    // 从 live 配置提取 token
                    if let Some(env) = live_config.get("env") {
                        if let Some(token) =
                            env.get("ANTHROPIC_AUTH_TOKEN").and_then(|v| v.as_str())
                        {
                            if !token.is_empty() {
                                // 更新 provider 的 settings_config
                                if let Some(env_obj) = provider
                                    .settings_config
                                    .get_mut("env")
                                    .and_then(|v| v.as_object_mut())
                                {
                                    env_obj
                                        .insert("ANTHROPIC_AUTH_TOKEN".to_string(), json!(token));
                                } else {
                                    provider.settings_config["env"] = json!({
                                        "ANTHROPIC_AUTH_TOKEN": token
                                    });
                                }
                                // 保存到数据库
                                if let Err(e) = self.db.update_provider_settings_config(
                                    "claude",
                                    &provider_id,
                                    &provider.settings_config,
                                ) {
                                    log::warn!("同步 Claude Token 到数据库失败: {e}");
                                } else {
                                    log::info!(
                                        "已同步 Claude Token 到数据库 (provider: {})",
                                        provider_id
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Codex: 同步 OPENAI_API_KEY
        if let Ok(live_config) = self.read_codex_live() {
            if let Some(provider_id) = self.db.get_current_provider("codex").ok().flatten() {
                if let Ok(Some(mut provider)) = self.db.get_provider_by_id(&provider_id, "codex") {
                    // 从 live 配置提取 token
                    if let Some(auth) = live_config.get("auth") {
                        if let Some(token) = auth.get("OPENAI_API_KEY").and_then(|v| v.as_str()) {
                            if !token.is_empty() {
                                // 更新 provider 的 settings_config
                                if let Some(auth_obj) = provider
                                    .settings_config
                                    .get_mut("auth")
                                    .and_then(|v| v.as_object_mut())
                                {
                                    auth_obj.insert("OPENAI_API_KEY".to_string(), json!(token));
                                } else {
                                    provider.settings_config["auth"] = json!({
                                        "OPENAI_API_KEY": token
                                    });
                                }
                                // 保存到数据库
                                if let Err(e) = self.db.update_provider_settings_config(
                                    "codex",
                                    &provider_id,
                                    &provider.settings_config,
                                ) {
                                    log::warn!("同步 Codex Token 到数据库失败: {e}");
                                } else {
                                    log::info!(
                                        "已同步 Codex Token 到数据库 (provider: {})",
                                        provider_id
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Gemini: 同步 GOOGLE_API_KEY
        if let Ok(live_config) = self.read_gemini_live() {
            if let Some(provider_id) = self.db.get_current_provider("gemini").ok().flatten() {
                if let Ok(Some(mut provider)) = self.db.get_provider_by_id(&provider_id, "gemini") {
                    // 从 live 配置提取 token
                    if let Some(env) = live_config.get("env") {
                        if let Some(token) = env.get("GOOGLE_API_KEY").and_then(|v| v.as_str()) {
                            if !token.is_empty() {
                                // 更新 provider 的 settings_config
                                if let Some(env_obj) = provider
                                    .settings_config
                                    .get_mut("env")
                                    .and_then(|v| v.as_object_mut())
                                {
                                    env_obj.insert("GOOGLE_API_KEY".to_string(), json!(token));
                                } else {
                                    provider.settings_config["env"] = json!({
                                        "GOOGLE_API_KEY": token
                                    });
                                }
                                // 保存到数据库
                                if let Err(e) = self.db.update_provider_settings_config(
                                    "gemini",
                                    &provider_id,
                                    &provider.settings_config,
                                ) {
                                    log::warn!("同步 Gemini Token 到数据库失败: {e}");
                                } else {
                                    log::info!(
                                        "已同步 Gemini Token 到数据库 (provider: {})",
                                        provider_id
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        log::info!("Live 配置 Token 同步完成");
        Ok(())
    }

    /// 停止代理服务器
    pub async fn stop(&self) -> Result<(), String> {
        if let Some(server) = self.server.write().await.take() {
            server
                .stop()
                .await
                .map_err(|e| format!("停止代理服务器失败: {e}"))?;

            // 将 enabled 设为 false，避免下次启动时自动开启
            if let Ok(mut config) = self.db.get_proxy_config().await {
                config.enabled = false;
                let _ = self.db.update_proxy_config(config).await;
            }

            log::info!("代理服务器已停止");
            Ok(())
        } else {
            Err("代理服务器未运行".to_string())
        }
    }

    /// 停止代理服务器（恢复 Live 配置）
    pub async fn stop_with_restore(&self) -> Result<(), String> {
        // 1. 停止代理服务器
        self.stop().await?;

        // 2. 恢复原始 Live 配置
        self.restore_live_configs().await?;

        // 3. 清除接管状态
        self.db
            .set_live_takeover_active(false)
            .await
            .map_err(|e| format!("清除接管状态失败: {e}"))?;

        // 4. 删除备份
        self.db
            .delete_all_live_backups()
            .await
            .map_err(|e| format!("删除备份失败: {e}"))?;

        log::info!("代理已停止，Live 配置已恢复");
        Ok(())
    }

    /// 崩溃恢复：仅恢复 Live 配置，不需要代理正在运行
    ///
    /// 用于应用启动时检测到上次异常退出（接管状态为 true 但代理未运行）的情况。
    pub async fn recover_from_crash(&self) -> Result<(), String> {
        log::info!("开始崩溃恢复...");

        // 1. 恢复原始 Live 配置
        self.restore_live_configs().await?;

        // 2. 清除接管状态
        self.db
            .set_live_takeover_active(false)
            .await
            .map_err(|e| format!("清除接管状态失败: {e}"))?;

        // 3. 删除备份
        self.db
            .delete_all_live_backups()
            .await
            .map_err(|e| format!("删除备份失败: {e}"))?;

        // 4. 确保 enabled 状态为 false，避免恢复后又自动启动
        if let Ok(mut config) = self.db.get_proxy_config().await {
            config.enabled = false;
            let _ = self.db.update_proxy_config(config).await;
        }

        log::info!("崩溃恢复完成，Live 配置已恢复");
        Ok(())
    }

    /// 备份各应用的 Live 配置
    async fn backup_live_configs(&self) -> Result<(), String> {
        // Claude
        if let Ok(config) = self.read_claude_live() {
            let json_str = serde_json::to_string(&config)
                .map_err(|e| format!("序列化 Claude 配置失败: {e}"))?;
            self.db
                .save_live_backup("claude", &json_str)
                .await
                .map_err(|e| format!("备份 Claude 配置失败: {e}"))?;
        }

        // Codex
        if let Ok(config) = self.read_codex_live() {
            let json_str = serde_json::to_string(&config)
                .map_err(|e| format!("序列化 Codex 配置失败: {e}"))?;
            self.db
                .save_live_backup("codex", &json_str)
                .await
                .map_err(|e| format!("备份 Codex 配置失败: {e}"))?;
        }

        // Gemini
        if let Ok(config) = self.read_gemini_live() {
            let json_str = serde_json::to_string(&config)
                .map_err(|e| format!("序列化 Gemini 配置失败: {e}"))?;
            self.db
                .save_live_backup("gemini", &json_str)
                .await
                .map_err(|e| format!("备份 Gemini 配置失败: {e}"))?;
        }

        log::info!("已备份所有应用的 Live 配置");
        Ok(())
    }

    /// 接管各应用的 Live 配置（写入代理地址）
    ///
    /// 代理服务器的路由已经根据 API 端点自动区分应用类型：
    /// - `/v1/messages` → Claude
    /// - `/v1/chat/completions`, `/v1/responses` → Codex
    /// - `/v1beta/*` → Gemini
    ///
    /// 因此不需要在 URL 中添加应用前缀。
    async fn takeover_live_configs(&self) -> Result<(), String> {
        let config = self
            .db
            .get_proxy_config()
            .await
            .map_err(|e| format!("获取代理配置失败: {e}"))?;

        let proxy_url = format!("http://{}:{}", config.listen_address, config.listen_port);

        // Claude: 修改 ANTHROPIC_BASE_URL，使用占位符替代真实 Token（代理会注入真实 Token）
        if let Ok(mut live_config) = self.read_claude_live() {
            if let Some(env) = live_config.get_mut("env").and_then(|v| v.as_object_mut()) {
                env.insert("ANTHROPIC_BASE_URL".to_string(), json!(&proxy_url));
                // 使用占位符，避免 Claude Code 显示缺少 key 的警告
                env.insert("ANTHROPIC_AUTH_TOKEN".to_string(), json!("PROXY_MANAGED"));
            } else {
                live_config["env"] = json!({
                    "ANTHROPIC_BASE_URL": &proxy_url,
                    "ANTHROPIC_AUTH_TOKEN": "PROXY_MANAGED"
                });
            }
            self.write_claude_live(&live_config)?;
            log::info!("Claude Live 配置已接管，代理地址: {}", proxy_url);
        }

        // Codex: 修改 OPENAI_BASE_URL，使用占位符替代真实 Token（代理会注入真实 Token）
        if let Ok(mut live_config) = self.read_codex_live() {
            if let Some(auth) = live_config.get_mut("auth").and_then(|v| v.as_object_mut()) {
                auth.insert("OPENAI_BASE_URL".to_string(), json!(&proxy_url));
                // 使用占位符，避免显示缺少 key 的警告
                auth.insert("OPENAI_API_KEY".to_string(), json!("PROXY_MANAGED"));
            }
            self.write_codex_live(&live_config)?;
            log::info!("Codex Live 配置已接管，代理地址: {}", proxy_url);
        }

        // Gemini: 修改 GEMINI_API_BASE，使用占位符替代真实 Token（代理会注入真实 Token）
        if let Ok(mut live_config) = self.read_gemini_live() {
            if let Some(env) = live_config.get_mut("env").and_then(|v| v.as_object_mut()) {
                env.insert("GEMINI_API_BASE".to_string(), json!(&proxy_url));
                // 使用占位符，避免显示缺少 key 的警告
                env.insert("GOOGLE_API_KEY".to_string(), json!("PROXY_MANAGED"));
            } else {
                live_config["env"] = json!({
                    "GEMINI_API_BASE": &proxy_url,
                    "GOOGLE_API_KEY": "PROXY_MANAGED"
                });
            }
            self.write_gemini_live(&live_config)?;
            log::info!("Gemini Live 配置已接管，代理地址: {}", proxy_url);
        }

        Ok(())
    }

    /// 恢复原始 Live 配置
    async fn restore_live_configs(&self) -> Result<(), String> {
        // Claude
        if let Ok(Some(backup)) = self.db.get_live_backup("claude").await {
            let config: Value = serde_json::from_str(&backup.original_config)
                .map_err(|e| format!("解析 Claude 备份失败: {e}"))?;
            self.write_claude_live(&config)?;
            log::info!("Claude Live 配置已恢复");
        }

        // Codex
        if let Ok(Some(backup)) = self.db.get_live_backup("codex").await {
            let config: Value = serde_json::from_str(&backup.original_config)
                .map_err(|e| format!("解析 Codex 备份失败: {e}"))?;
            self.write_codex_live(&config)?;
            log::info!("Codex Live 配置已恢复");
        }

        // Gemini
        if let Ok(Some(backup)) = self.db.get_live_backup("gemini").await {
            let config: Value = serde_json::from_str(&backup.original_config)
                .map_err(|e| format!("解析 Gemini 备份失败: {e}"))?;
            self.write_gemini_live(&config)?;
            log::info!("Gemini Live 配置已恢复");
        }

        Ok(())
    }

    /// 检查是否处于 Live 接管模式
    pub async fn is_takeover_active(&self) -> Result<bool, String> {
        self.db
            .is_live_takeover_active()
            .await
            .map_err(|e| format!("检查接管状态失败: {e}"))
    }

    /// 代理模式下切换供应商（热切换，不写 Live）
    pub async fn switch_proxy_target(
        &self,
        app_type: &str,
        provider_id: &str,
    ) -> Result<(), String> {
        // 更新数据库中的 is_current 标记
        let app_type_enum =
            AppType::from_str(app_type).map_err(|_| format!("无效的应用类型: {app_type}"))?;

        self.db
            .set_current_provider(app_type_enum.as_str(), provider_id)
            .map_err(|e| format!("更新当前供应商失败: {e}"))?;

        log::info!(
            "代理模式：已切换 {} 的目标供应商为 {}",
            app_type,
            provider_id
        );
        Ok(())
    }

    // ==================== Live 配置读写辅助方法 ====================

    fn read_claude_live(&self) -> Result<Value, String> {
        let path = get_claude_settings_path();
        if !path.exists() {
            return Err("Claude 配置文件不存在".to_string());
        }
        read_json_file(&path).map_err(|e| format!("读取 Claude 配置失败: {e}"))
    }

    fn write_claude_live(&self, config: &Value) -> Result<(), String> {
        let path = get_claude_settings_path();
        write_json_file(&path, config).map_err(|e| format!("写入 Claude 配置失败: {e}"))
    }

    fn read_codex_live(&self) -> Result<Value, String> {
        use crate::codex_config::{get_codex_auth_path, get_codex_config_path};

        let auth_path = get_codex_auth_path();
        if !auth_path.exists() {
            return Err("Codex auth.json 不存在".to_string());
        }

        let auth: Value =
            read_json_file(&auth_path).map_err(|e| format!("读取 Codex auth 失败: {e}"))?;

        let config_path = get_codex_config_path();
        let config_str = if config_path.exists() {
            std::fs::read_to_string(&config_path)
                .map_err(|e| format!("读取 Codex config 失败: {e}"))?
        } else {
            String::new()
        };

        Ok(json!({
            "auth": auth,
            "config": config_str
        }))
    }

    fn write_codex_live(&self, config: &Value) -> Result<(), String> {
        use crate::codex_config::{get_codex_auth_path, get_codex_config_path};

        if let Some(auth) = config.get("auth") {
            let auth_path = get_codex_auth_path();
            write_json_file(&auth_path, auth).map_err(|e| format!("写入 Codex auth 失败: {e}"))?;
        }

        if let Some(config_str) = config.get("config").and_then(|v| v.as_str()) {
            let config_path = get_codex_config_path();
            std::fs::write(&config_path, config_str)
                .map_err(|e| format!("写入 Codex config 失败: {e}"))?;
        }

        Ok(())
    }

    fn read_gemini_live(&self) -> Result<Value, String> {
        use crate::gemini_config::{env_to_json, get_gemini_env_path, read_gemini_env};

        let env_path = get_gemini_env_path();
        if !env_path.exists() {
            return Err("Gemini .env 文件不存在".to_string());
        }

        let env_map = read_gemini_env().map_err(|e| format!("读取 Gemini env 失败: {e}"))?;
        Ok(env_to_json(&env_map))
    }

    fn write_gemini_live(&self, config: &Value) -> Result<(), String> {
        use crate::gemini_config::{json_to_env, write_gemini_env_atomic};

        let env_map = json_to_env(config).map_err(|e| format!("转换 Gemini 配置失败: {e}"))?;
        write_gemini_env_atomic(&env_map).map_err(|e| format!("写入 Gemini env 失败: {e}"))?;
        Ok(())
    }

    // ==================== 原有方法 ====================

    /// 获取服务器状态
    pub async fn get_status(&self) -> Result<ProxyStatus, String> {
        if let Some(server) = self.server.read().await.as_ref() {
            Ok(server.get_status().await)
        } else {
            // 服务器未运行时返回默认状态
            Ok(ProxyStatus {
                running: false,
                ..Default::default()
            })
        }
    }

    /// 获取代理配置
    pub async fn get_config(&self) -> Result<ProxyConfig, String> {
        self.db
            .get_proxy_config()
            .await
            .map_err(|e| format!("获取代理配置失败: {e}"))
    }

    /// 更新代理配置
    pub async fn update_config(&self, config: &ProxyConfig) -> Result<(), String> {
        // 记录旧配置用于判定是否需要重启
        let previous = self
            .db
            .get_proxy_config()
            .await
            .map_err(|e| format!("获取代理配置失败: {e}"))?;

        // 保存到数据库（保持 enabled 和 live_takeover_active 状态不变）
        let mut new_config = config.clone();
        new_config.enabled = previous.enabled;
        new_config.live_takeover_active = previous.live_takeover_active;

        self.db
            .update_proxy_config(new_config.clone())
            .await
            .map_err(|e| format!("保存代理配置失败: {e}"))?;

        // 检查服务器当前状态
        let mut server_guard = self.server.write().await;
        if server_guard.is_none() {
            return Ok(());
        }

        // 判断是否需要重启（地址或端口变更）
        let require_restart = new_config.listen_address != previous.listen_address
            || new_config.listen_port != previous.listen_port;

        if require_restart {
            if let Some(server) = server_guard.take() {
                server
                    .stop()
                    .await
                    .map_err(|e| format!("重启前停止代理服务器失败: {e}"))?;
            }

            let new_server = ProxyServer::new(new_config, self.db.clone());
            new_server
                .start()
                .await
                .map_err(|e| format!("重启代理服务器失败: {e}"))?;

            *server_guard = Some(new_server);
            log::info!("代理配置已更新，服务器已自动重启应用最新配置");
        } else if let Some(server) = server_guard.as_ref() {
            server.apply_runtime_config(&new_config).await;
            log::info!("代理配置已实时应用，无需重启代理服务器");
        }

        Ok(())
    }

    /// 检查服务器是否正在运行
    pub async fn is_running(&self) -> bool {
        self.server.read().await.is_some()
    }
}
