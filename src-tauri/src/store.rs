use crate::database::Database;
use crate::services::{ProxyService, SshService};
use std::sync::Arc;

/// 全局应用状态
pub struct AppState {
    pub db: Arc<Database>,
    pub proxy_service: ProxyService,
    pub ssh_service: SshService,
}

impl AppState {
    /// 创建新的应用状态
    pub fn new(db: Arc<Database>) -> Self {
        let ssh_service = SshService::new();
        let ssh_service_arc = Arc::new(ssh_service.clone());

        let proxy_service = ProxyService::new(db.clone())
            .with_ssh_service(ssh_service_arc);

        Self {
            db,
            proxy_service,
            ssh_service,
        }
    }
}
