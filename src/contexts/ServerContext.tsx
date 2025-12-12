import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
} from "react";
import type { ManagedServer, ManagedServersMap } from "../types/server";

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

  // 操作方法
  selectServer: (serverId: string) => void;
  goBackToServerHome: () => void;
  addServer: (server: Omit<ManagedServer, "id" | "createdAt">) => void;
  updateServer: (server: ManagedServer) => void;
  removeServer: (serverId: string) => void;
  refreshServers: () => void;
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

  // 选择服务器（进入二级页面）
  const selectServer = useCallback((serverId: string) => {
    setCurrentServerId(serverId);
  }, []);

  // 返回服务器管理主页（一级页面）
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

  // 刷新服务器列表（目前只是触发重新渲染）
  const refreshServers = useCallback(() => {
    // 未来可以添加 SSH 连接状态检查等逻辑
    setServers((prev) => ({ ...prev }));
  }, []);

  const value: ServerContextValue = {
    servers,
    currentServer,
    currentServerId,
    isOnServerHome,
    selectServer,
    goBackToServerHome,
    addServer,
    updateServer,
    removeServer,
    refreshServers,
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
