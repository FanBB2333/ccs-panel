import {
  keepPreviousData,
  useQuery,
  type UseQueryResult,
} from "@tanstack/react-query";
import {
  providersApi,
  sessionsApi,
  settingsApi,
  sshApi,
  usageApi,
  type AppId,
} from "@/lib/api";
import type {
  Provider,
  SessionMessage,
  SessionMeta,
  Settings,
  UsageResult,
} from "@/types";
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

const parseRemoteProviders = (
  remoteData: unknown,
): Record<string, Provider> => {
  if (!Array.isArray(remoteData)) {
    console.warn("[parseRemoteProviders] Invalid data format:", remoteData);
    return {};
  }

  const result: Record<string, Provider> = {};

  for (const item of remoteData as any[]) {
    try {
      const settingsConfigRaw = item.settingsConfig ?? item.settings_config;
      const provider: Provider = {
        id: item.id,
        name: item.name,
        settingsConfig:
          typeof settingsConfigRaw === "string"
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

      if (item.meta) {
        const metaRaw =
          typeof item.meta === "string" ? JSON.parse(item.meta) : item.meta;
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
  isProxyRunning?: boolean;
  server?: ManagedServer | null;
}

export const useProvidersQuery = (
  appId: AppId,
  options?: UseProvidersQueryOptions,
): UseQueryResult<ProvidersQueryData> => {
  const { isProxyRunning = false, server = null } = options || {};
  const isRemote =
    server !== null && !server.isLocal && server.connectionType === "ssh";
  const serverId = server?.id;

  return useQuery({
    queryKey: ["providers", appId, serverId || "local"],
    placeholderData: keepPreviousData,
    refetchInterval: isProxyRunning && !isRemote ? 10000 : false,
    queryFn: async () => {
      let providers: Record<string, Provider> = {};
      let currentProviderId = "";

      if (isRemote && serverId) {
        try {
          const remoteConfig = await sshApi.readRemoteConfig(serverId, appId);
          providers = parseRemoteProviders(remoteConfig.providers);
          currentProviderId = remoteConfig.current_provider_id || "";
        } catch (error) {
          console.error("获取远程供应商列表失败:", error);
        }
      } else {
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
  autoQueryInterval?: number;
}

export const useUsageQuery = (
  providerId: string,
  appId: AppId,
  options?: UseUsageQueryOptions,
) => {
  const { enabled = true, autoQueryInterval = 0 } = options || {};

  const staleTime =
    autoQueryInterval > 0
      ? autoQueryInterval * 60 * 1000
      : 5 * 60 * 1000;

  const query = useQuery<UsageResult>({
    queryKey: ["usage", providerId, appId],
    queryFn: async () => usageApi.query(providerId, appId),
    enabled: enabled && !!providerId,
    refetchInterval:
      autoQueryInterval > 0
        ? Math.max(autoQueryInterval, 1) * 60 * 1000
        : false,
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    retry: false,
    staleTime,
    gcTime: 10 * 60 * 1000,
  });

  return {
    ...query,
    lastQueriedAt: query.dataUpdatedAt || null,
  };
};

export const useSessionsQuery = () => {
  return useQuery<SessionMeta[]>({
    queryKey: ["sessions"],
    queryFn: async () => sessionsApi.list(),
    staleTime: 30 * 1000,
  });
};

export const useSessionMessagesQuery = (
  providerId?: string,
  sourcePath?: string,
) => {
  return useQuery<SessionMessage[]>({
    queryKey: ["sessionMessages", providerId, sourcePath],
    queryFn: async () => sessionsApi.getMessages(providerId!, sourcePath!),
    enabled: Boolean(providerId && sourcePath),
    staleTime: 30 * 1000,
  });
};
