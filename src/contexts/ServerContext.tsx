import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
} from "react";
import { toast } from "sonner";
import type { ManagedServer, ManagedServersMap } from "../types/server";
import { sshApi, type SshConnectRequest } from "../lib/api";

// 本地服务器的固定 ID
const LOCAL_SERVER_ID = "local";

// 创建默认的本地服务器
const createLocalServer = (): ManagedServer => ({
  id: LOCAL_SERVER_ID,
  name: "本地服务器",
  connectionType: "local",
  status: "connected",
  isLocal: true,
  createdAt: Date.now(),
});

interface ServerContextValue {
  // 服务器列表
  servers: ManagedServersMap;
  // 当前选中的服务器
  currentServer: ManagedServer | null;
  currentServerId: string | null;
  // 是否在服务器管理主页（一级页面）
  isOnServerHome: boolean;
  // 是否正在连接
  isConnecting: boolean;

  // 操作方法
  selectServer: (serverId: string) => void;
  goBackToServerHome: () => void;
  addServer: (server: Omit<ManagedServer, "id" | "createdAt">) => void;
  updateServer: (server: ManagedServer) => void;
  removeServer: (serverId: string) => void;
  refreshServers: () => void;
  connectToServer: (serverId: string) => Promise<boolean>;
  disconnectFromServer: (serverId: string) => Promise<void>;
  testServerConnection: (server: ManagedServer) => Promise<boolean>;
}

const ServerContext = createContext<ServerContextValue | undefined>(undefined);

const STORAGE_KEY = "ccs-panel:servers";
const CURRENT_SERVER_KEY = "ccs-panel:currentServer";

export function ServerProvider({ children }: { children: React.ReactNode }) {
  const [servers, setServers] = useState<ManagedServersMap>(() => {
    // 从 localStorage 加载服务器列表
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as ManagedServersMap;
        // 确保本地服务器始终存在
        if (!parsed[LOCAL_SERVER_ID]) {
          parsed[LOCAL_SERVER_ID] = createLocalServer();
        }
        // 远程服务器启动时重置为未连接状态
        Object.keys(parsed).forEach((id) => {
          if (id !== LOCAL_SERVER_ID) {
            parsed[id].status = "disconnected";
          }
        });
        return parsed;
      }
    } catch (error) {
      console.error("[ServerContext] Failed to load servers from storage:", error);
    }
    // 默认只有本地服务器
    return { [LOCAL_SERVER_ID]: createLocalServer() };
  });

  const [currentServerId, setCurrentServerId] = useState<string | null>(() => {
    // 应用启动时始终显示服务器管理主页
    // 用户需要主动选择一个服务器才能进入管理界面
    return null;
  });

  const [isConnecting, setIsConnecting] = useState(false);

  // 是否在服务器管理主页
  const isOnServerHome = currentServerId === null;

  // 当前选中的服务器对象
  const currentServer = currentServerId ? servers[currentServerId] || null : null;

  // 持久化服务器列表
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(servers));
    } catch (error) {
      console.error("[ServerContext] Failed to save servers to storage:", error);
    }
  }, [servers]);

  // 持久化当前选中的服务器
  useEffect(() => {
    try {
      if (currentServerId) {
        localStorage.setItem(CURRENT_SERVER_KEY, currentServerId);
      } else {
        localStorage.removeItem(CURRENT_SERVER_KEY);
      }
    } catch (error) {
      console.error("[ServerContext] Failed to save current server to storage:", error);
    }
  }, [currentServerId]);

  // 更新服务器状态
  const updateServerStatus = useCallback(
    (serverId: string, status: ManagedServer["status"]) => {
      setServers((prev) => ({
        ...prev,
        [serverId]: {
          ...prev[serverId],
          status,
          lastConnected: status === "connected" ? Date.now() : prev[serverId]?.lastConnected,
        },
      }));
    },
    []
  );

  // 连接到远程服务器
  const connectToServer = useCallback(
    async (serverId: string): Promise<boolean> => {
      const server = servers[serverId];
      if (!server) {
        console.error("[ServerContext] Server not found:", serverId);
        return false;
      }

      // 本地服务器不需要连接
      if (server.isLocal) {
        return true;
      }

      if (!server.sshConfig) {
        console.error("[ServerContext] SSH config not found for server:", serverId);
        toast.error("SSH 配置缺失");
        return false;
      }

      setIsConnecting(true);
      updateServerStatus(serverId, "connecting");

      try {
        const request: SshConnectRequest = {
          server_id: serverId,
          host: server.sshConfig.host,
          port: server.sshConfig.port,
          username: server.sshConfig.username,
          auth_type: server.sshConfig.authType,
          password: server.sshConfig.password,
          private_key_path: server.sshConfig.privateKeyPath,
          passphrase: server.sshConfig.passphrase,
          sqlite3_path: server.sshConfig.sqlite3Path,
        };

        await sshApi.connect(request);
        updateServerStatus(serverId, "connected");
        toast.success(`已连接到 ${server.name}`);
        return true;
      } catch (error) {
        console.error("[ServerContext] Failed to connect:", error);
        updateServerStatus(serverId, "error");
        toast.error(`连接失败: ${error instanceof Error ? error.message : String(error)}`);
        return false;
      } finally {
        setIsConnecting(false);
      }
    },
    [servers, updateServerStatus]
  );

  // 断开远程服务器连接
  const disconnectFromServer = useCallback(
    async (serverId: string): Promise<void> => {
      const server = servers[serverId];
      if (!server || server.isLocal) {
        return;
      }

      try {
        await sshApi.disconnect(serverId);
        updateServerStatus(serverId, "disconnected");
      } catch (error) {
        console.error("[ServerContext] Failed to disconnect:", error);
      }
    },
    [servers, updateServerStatus]
  );

  // 测试服务器连接
  const testServerConnection = useCallback(
    async (server: ManagedServer): Promise<boolean> => {
      if (server.isLocal) {
        return true;
      }

      if (!server.sshConfig) {
        toast.error("SSH 配置缺失");
        return false;
      }

      try {
        const request: SshConnectRequest = {
          server_id: server.id,
          host: server.sshConfig.host,
          port: server.sshConfig.port,
          username: server.sshConfig.username,
          auth_type: server.sshConfig.authType,
          password: server.sshConfig.password,
          private_key_path: server.sshConfig.privateKeyPath,
          passphrase: server.sshConfig.passphrase,
          sqlite3_path: server.sshConfig.sqlite3Path,
        };

        const result = await sshApi.testConnection(request);
        if (result) {
          toast.success("连接测试成功");
        }
        return result;
      } catch (error) {
        console.error("[ServerContext] Connection test failed:", error);
        toast.error(`连接测试失败: ${error instanceof Error ? error.message : String(error)}`);
        return false;
      }
    },
    []
  );

  // 选择服务器（进入二级页面）- 对于远程服务器，如果未连接会先尝试连接
  const selectServer = useCallback(
    async (serverId: string) => {
      const server = servers[serverId];
      if (!server) {
        return;
      }

      // 本地服务器直接进入
      if (server.isLocal) {
        setCurrentServerId(serverId);
        return;
      }

      // 远程服务器：检查是否已连接
      if (server.status === "connected") {
        // 已连接，直接进入
        setCurrentServerId(serverId);
        return;
      }

      // 未连接，先建立连接
      const connected = await connectToServer(serverId);
      if (connected) {
        setCurrentServerId(serverId);
      }
    },
    [servers, connectToServer]
  );

  // 返回服务器管理主页（一级页面）- 不断开连接，保持连接状态
  const goBackToServerHome = useCallback(() => {
    setCurrentServerId(null);
  }, []);

  // 添加服务器
  const addServer = useCallback(
    (serverData: Omit<ManagedServer, "id" | "createdAt">) => {
      const id = `server-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      const newServer: ManagedServer = {
        ...serverData,
        id,
        createdAt: Date.now(),
      };
      setServers((prev) => ({
        ...prev,
        [id]: newServer,
      }));
    },
    []
  );

  // 更新服务器
  const updateServer = useCallback((server: ManagedServer) => {
    setServers((prev) => ({
      ...prev,
      [server.id]: server,
    }));
  }, []);

  // 删除服务器（本地服务器不能删除）
  const removeServer = useCallback((serverId: string) => {
    if (serverId === LOCAL_SERVER_ID) {
      console.warn("[ServerContext] Cannot remove local server");
      return;
    }
    setServers((prev) => {
      const next = { ...prev };
      delete next[serverId];
      return next;
    });
    // 如果删除的是当前选中的服务器，返回主页
    setCurrentServerId((prev) => (prev === serverId ? null : prev));
  }, []);

  // 刷新服务器列表（检查连接状态）
  const refreshServers = useCallback(async () => {
    const serverIds = Object.keys(servers).filter((id) => id !== LOCAL_SERVER_ID);

    for (const serverId of serverIds) {
      try {
        const status = await sshApi.getStatus(serverId);
        updateServerStatus(serverId, status.status);
      } catch {
        // 忽略错误，保持当前状态
      }
    }
  }, [servers, updateServerStatus]);

  const value: ServerContextValue = {
    servers,
    currentServer,
    currentServerId,
    isOnServerHome,
    isConnecting,
    selectServer,
    goBackToServerHome,
    addServer,
    updateServer,
    removeServer,
    refreshServers,
    connectToServer,
    disconnectFromServer,
    testServerConnection,
  };

  return (
    <ServerContext.Provider value={value}>{children}</ServerContext.Provider>
  );
}

export function useServer() {
  const context = useContext(ServerContext);
  if (!context) {
    throw new Error("useServer must be used within ServerProvider");
  }
  return context;
}
