// 服务器连接类型
export type ServerConnectionType = "local" | "ssh";

// SSH 认证方式
export type SSHAuthType = "password" | "key";

// SSH 连接配置
export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  authType: SSHAuthType;
  password?: string;
  privateKeyPath?: string;
  passphrase?: string;
  /** 远程 sqlite3 可执行文件路径（可选，如 /usr/bin/sqlite3） */
  sqlite3Path?: string;
}

// 服务器状态
export type ServerStatus = "connected" | "disconnected" | "connecting" | "error";

// 服务器配置
export interface ManagedServer {
  id: string;
  name: string;
  connectionType: ServerConnectionType;
  sshConfig?: SSHConfig;
  status: ServerStatus;
  lastConnected?: number;
  createdAt: number;
  // 本地服务器标记
  isLocal?: boolean;
}

// 服务器列表
export type ManagedServersMap = Record<string, ManagedServer>;
