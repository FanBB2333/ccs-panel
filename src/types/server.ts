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

// 远程服务器配置目录（用于覆盖默认路径）
export interface RemoteConfigDirs {
  claudeConfigDir?: string;
  codexConfigDir?: string;
  geminiConfigDir?: string;
  /** 远程服务器的工作目录（CCS Panel 数据库路径） */
  workingDir?: string;
}

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
  // 远程服务器配置目录（仅对远程服务器有效）
  configDirs?: RemoteConfigDirs;
}

// 服务器列表
export type ManagedServersMap = Record<string, ManagedServer>;
