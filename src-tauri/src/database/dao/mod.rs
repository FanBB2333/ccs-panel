//! Data Access Object layer
//!
//! Database access operations for each domain

pub mod mcp;
pub mod prompts;
pub mod provider_store;
pub mod providers;
pub mod proxy;
pub mod settings;
pub mod skills;
pub mod stream_check;

// Re-export ProviderStore trait and LocalProviderStore for external use
pub use provider_store::{LocalProviderStore, ProviderStore};

// 所有 DAO 方法都通过 Database impl 提供，无需单独导出
