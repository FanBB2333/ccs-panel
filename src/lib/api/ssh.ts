import { invoke } from "@tauri-apps/api/core";

/**
 * SSH 连接请求参数
 */
export interface SshConnectRequest {
  server_id: string;
  host: string;
  port: number;
  username: string;
  auth_type: "password" | "key";
  password?: string;
  private_key_path?: string;
  passphrase?: string;
  /** 远程 sqlite3 可执行文件路径（可选） */
  sqlite3_path?: string;
}

/**
 * SSH 状态响应
 */
export interface SshStatusResponse {
  server_id: string;
  status: "connected" | "disconnected" | "connecting" | "error";
}

/**
 * 远程配置数据
 */
export interface RemoteConfig {
  providers: unknown;
  current_provider_id: string | null;
}

/**
 * SSH API 封装
 */
export const sshApi = {
  /**
   * 连接到远程服务器
   */
  connect: async (request: SshConnectRequest): Promise<SshStatusResponse> => {
    return invoke("ssh_connect", { request });
  },

  /**
   * 断开远程服务器连接
   */
  disconnect: async (serverId: string): Promise<SshStatusResponse> => {
    return invoke("ssh_disconnect", { serverId });
  },

  /**
   * 获取连接状态
   */
  getStatus: async (serverId: string): Promise<SshStatusResponse> => {
    return invoke("ssh_get_status", { serverId });
  },

  /**
   * 测试 SSH 连接
   */
  testConnection: async (request: SshConnectRequest): Promise<boolean> => {
    return invoke("ssh_test_connection", { request });
  },

  /**
   * 读取远程配置
   */
  readRemoteConfig: async (
    serverId: string,
    appType: string
  ): Promise<RemoteConfig> => {
    return invoke("ssh_read_remote_config", { serverId, appType });
  },

  /**
   * 在远程服务器执行命令
   */
  execute: async (serverId: string, command: string): Promise<string> => {
    return invoke("ssh_execute", { serverId, command });
  },

  /**
   * 添加远程供应商
   */
  addRemoteProvider: async (
    serverId: string,
    provider: unknown,
    appType: string
  ): Promise<void> => {
    return invoke("ssh_add_remote_provider", { serverId, provider, appType });
  },

  /**
   * 切换远程供应商（设置当前供应商）
   */
  switchRemoteProvider: async (
    serverId: string,
    providerId: string,
    appType: string
  ): Promise<void> => {
    return invoke("ssh_switch_remote_provider", { serverId, providerId, appType });
  },
};
