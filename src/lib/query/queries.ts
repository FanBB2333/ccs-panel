import {
  useQuery,
  type UseQueryResult,
  keepPreviousData,
} from "@tanstack/react-query";
import { providersApi, settingsApi, usageApi, sshApi, type AppId } from "@/lib/api";
import type { Provider, Settings, UsageResult } from "@/types";
import type { ManagedServer } from "@/types/server";

const sortProviders = (
  providers: Record<string, Provider>,
): Record<string, Provider> => {
  const sortedEntries = Object.values(providers)
    .sort((a, b) => {
      const indexA = a.sortIndex ?? Number.MAX_SAFE_INTEGER;
      const indexB = b.sortIndex ?? Number.MAX_SAFE_INTEGER;
      if (indexA !== indexB) {
        return indexA - indexB;
      }

      const timeA = a.createdAt ?? 0;
      const timeB = b.createdAt ?? 0;
      if (timeA === timeB) {
        return a.name.localeCompare(b.name, "zh-CN");
      }
      return timeA - timeB;
    })
    .map((provider) => [provider.id, provider] as const);

  return Object.fromEntries(sortedEntries);
};

/**
 * 将远程返回的 JSON 数据转换为 Provider 格式
 * 支持 camelCase 和 snake_case 两种格式
 */
const parseRemoteProviders = (
  remoteData: unknown
): Record<string, Provider> => {
  if (!Array.isArray(remoteData)) {
    console.warn("[parseRemoteProviders] Invalid data format:", remoteData);
    return {};
  }

  const result: Record<string, Provider> = {};

  for (const item of remoteData) {
    try {
      // 支持 camelCase 和 snake_case 两种格式
      const settingsConfigRaw = item.settingsConfig ?? item.settings_config;
      const provider: Provider = {
        id: item.id,
        name: item.name,
        settingsConfig: typeof settingsConfigRaw === "string"
          ? JSON.parse(settingsConfigRaw)
          : settingsConfigRaw || {},
        websiteUrl: item.websiteUrl ?? item.website_url,
        category: item.category,
        createdAt: item.createdAt ?? item.created_at,
        sortIndex: item.sortIndex ?? item.sort_index,
        notes: item.notes,
        icon: item.icon,
        iconColor: item.iconColor ?? item.icon_color,
        isProxyTarget: item.isProxyTarget ?? item.is_proxy_target,
      };

      // 处理 meta 字段
      if (item.meta) {
        const metaRaw = typeof item.meta === "string" ? JSON.parse(item.meta) : item.meta;
        if (metaRaw && typeof metaRaw === "object") {
          provider.meta = metaRaw;
        }
      }

      result[provider.id] = provider;
    } catch (error) {
      console.error("[parseRemoteProviders] Failed to parse provider:", item, error);
    }
  }

  return result;
};

export interface ProvidersQueryData {
  providers: Record<string, Provider>;
  currentProviderId: string;
}

export interface UseProvidersQueryOptions {
  isProxyRunning?: boolean; // 代理服务是否运行中
  server?: ManagedServer | null; // 当前管理的服务器配置
}

export const useProvidersQuery = (
  appId: AppId,
  options?: UseProvidersQueryOptions,
): UseQueryResult<ProvidersQueryData> => {
  const { isProxyRunning = false, server = null } = options || {};

  // 判断是否从远程加载：有 server 且不是本地服务器
  const isRemote = server !== null && !server.isLocal && server.connectionType === "ssh";
  const serverId = server?.id;

  return useQuery({
    queryKey: ["providers", appId, serverId || "local"],
    placeholderData: keepPreviousData,
    // 当代理服务运行时，每 10 秒刷新一次供应商列表
    // 这样可以自动反映后端熔断器自动禁用代理目标的变更
    // 远程服务器不自动刷新
    refetchInterval: isProxyRunning && !isRemote ? 10000 : false,
    queryFn: async () => {
      let providers: Record<string, Provider> = {};
      let currentProviderId = "";

      if (isRemote && serverId) {
        // 远程服务器：从 SSH 加载配置
        try {
          console.log("[useProvidersQuery] Loading remote config for server:", serverId, "app:", appId);
          // 使用当前管理的服务器配置读取远程文件
          const remoteConfig = await sshApi.readRemoteConfig(serverId, appId);
          providers = parseRemoteProviders(remoteConfig.providers);
          currentProviderId = remoteConfig.current_provider_id || "";
          console.log("[useProvidersQuery] Loaded", Object.keys(providers).length, "providers from remote");
        } catch (error) {
          console.error("获取远程供应商列表失败:", error);
        }
      } else {
        // 本地服务器：读取本地配置文件
        try {
          providers = await providersApi.getAll(appId);
        } catch (error) {
          console.error("获取供应商列表失败:", error);
        }

        try {
          currentProviderId = await providersApi.getCurrent(appId);
        } catch (error) {
          console.error("获取当前供应商失败:", error);
        }

        if (Object.keys(providers).length === 0) {
          try {
            const success = await providersApi.importDefault(appId);
            if (success) {
              providers = await providersApi.getAll(appId);
              currentProviderId = await providersApi.getCurrent(appId);
            }
          } catch (error) {
            console.error("导入默认配置失败:", error);
          }
        }
      }

      return {
        providers: sortProviders(providers),
        currentProviderId,
      };
    },
  });
};

export const useSettingsQuery = (): UseQueryResult<Settings> => {
  return useQuery({
    queryKey: ["settings"],
    queryFn: async () => settingsApi.get(),
  });
};

export interface UseUsageQueryOptions {
  enabled?: boolean;
  autoQueryInterval?: number; // 自动查询间隔（分钟），0 表示禁用
}

export const useUsageQuery = (
  providerId: string,
  appId: AppId,
  options?: UseUsageQueryOptions,
) => {
  const { enabled = true, autoQueryInterval = 0 } = options || {};

  // 计算 staleTime：如果有自动刷新间隔，使用该间隔；否则默认 5 分钟
  // 这样可以避免切换 app 页面时重复触发查询
  const staleTime =
    autoQueryInterval > 0
      ? autoQueryInterval * 60 * 1000 // 与刷新间隔保持一致
      : 5 * 60 * 1000; // 默认 5 分钟

  const query = useQuery<UsageResult>({
    queryKey: ["usage", providerId, appId],
    queryFn: async () => usageApi.query(providerId, appId),
    enabled: enabled && !!providerId,
    refetchInterval:
      autoQueryInterval > 0
        ? Math.max(autoQueryInterval, 1) * 60 * 1000 // 最小1分钟
        : false,
    refetchIntervalInBackground: true, // 后台也继续定时查询
    refetchOnWindowFocus: false,
    retry: false,
    staleTime, // 使用动态计算的缓存时间
    gcTime: 10 * 60 * 1000, // 缓存保留 10 分钟（组件卸载后）
  });

  return {
    ...query,
    lastQueriedAt: query.dataUpdatedAt || null,
  };
};
