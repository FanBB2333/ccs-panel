//! Provider 存储抽象层
//!
//! 定义统一的 Provider 存储接口，支持本地和远程实现。

use crate::error::AppError;
use crate::provider::Provider;
use indexmap::IndexMap;
use serde_json::Value;

/// Provider 存储抽象 trait
///
/// 提供统一的 Provider CRUD 接口，本地和远程实现均需实现此 trait。
pub trait ProviderStore {
    /// 获取指定应用类型的所有供应商
    fn get_all_providers(&self, app_type: &str) -> Result<IndexMap<String, Provider>, AppError>;

    /// 根据 ID 获取单个供应商
    fn get_provider_by_id(&self, id: &str, app_type: &str) -> Result<Option<Provider>, AppError>;

    /// 保存供应商（新增或更新）
    fn save_provider(&self, app_type: &str, provider: &Provider) -> Result<(), AppError>;

    /// 删除供应商
    fn delete_provider(&self, app_type: &str, id: &str) -> Result<(), AppError>;

    /// 获取当前激活的供应商 ID
    fn get_current_provider(&self, app_type: &str) -> Result<Option<String>, AppError>;

    /// 设置当前供应商
    fn set_current_provider(&self, app_type: &str, id: &str) -> Result<(), AppError>;

    /// 设置代理目标供应商
    fn set_proxy_target_provider(&self, app_type: &str, id: &str) -> Result<(), AppError>;

    /// 写入 live 配置（切换 provider 时调用）
    ///
    /// 本地实现写入 ~/.claude/settings.json 等文件
    /// 远程实现通过 SSH 写入远程服务器的相应文件
    fn write_live_config(&self, app_type: &str, settings_config: &Value) -> Result<(), AppError>;
}

/// 本地 Provider 存储实现
///
/// 包装 Database 实例，委托给现有的 DAO 方法
pub struct LocalProviderStore<'a> {
    db: &'a crate::database::Database,
}

impl<'a> LocalProviderStore<'a> {
    pub fn new(db: &'a crate::database::Database) -> Self {
        Self { db }
    }
}

impl ProviderStore for LocalProviderStore<'_> {
    fn get_all_providers(&self, app_type: &str) -> Result<IndexMap<String, Provider>, AppError> {
        self.db.get_all_providers(app_type)
    }

    fn get_provider_by_id(&self, id: &str, app_type: &str) -> Result<Option<Provider>, AppError> {
        self.db.get_provider_by_id(id, app_type)
    }

    fn save_provider(&self, app_type: &str, provider: &Provider) -> Result<(), AppError> {
        self.db.save_provider(app_type, provider)
    }

    fn delete_provider(&self, app_type: &str, id: &str) -> Result<(), AppError> {
        self.db.delete_provider(app_type, id)
    }

    fn get_current_provider(&self, app_type: &str) -> Result<Option<String>, AppError> {
        self.db.get_current_provider(app_type)
    }

    fn set_current_provider(&self, app_type: &str, id: &str) -> Result<(), AppError> {
        self.db.set_current_provider(app_type, id)
    }

    fn set_proxy_target_provider(&self, app_type: &str, id: &str) -> Result<(), AppError> {
        self.db.set_proxy_target_provider(app_type, id)
    }

    fn write_live_config(&self, app_type: &str, settings_config: &Value) -> Result<(), AppError> {
        use crate::app_config::AppType;
        use std::str::FromStr;

        let app_type = AppType::from_str(app_type).map_err(|e| AppError::Message(e.to_string()))?;

        // 创建一个临时 Provider 来调用现有的 write_live_snapshot
        let provider = Provider {
            id: String::new(),
            name: String::new(),
            settings_config: settings_config.clone(),
            website_url: None,
            category: None,
            created_at: None,
            sort_index: None,
            notes: None,
            meta: None,
            icon: None,
            icon_color: None,
            is_proxy_target: None,
        };

        crate::services::provider::write_live_snapshot(&app_type, &provider)
    }
}
