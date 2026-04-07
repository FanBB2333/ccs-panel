/**
 * 代理服务状态管理 Hook
 */

import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import type {
  ProxyServerInfo,
  ProxyStatus,
  ProxyTakeoverStatus,
} from "@/types/proxy";
import { extractErrorMessage } from "@/utils/errorUtils";

interface UseProxyStatusOptions {
  serverId?: string | null;
}

/**
 * 代理服务状态管理
 * @param options.serverId - 服务器 ID，用于区分本地模式和远程服务器模式
 */
export function useProxyStatus(options: UseProxyStatusOptions = {}) {
  const { serverId } = options;
  const isRemoteServer = serverId != null && serverId !== "local";

  const serverIdRef = useRef(serverId);
  const isRemoteServerRef = useRef(isRemoteServer);

  useEffect(() => {
    serverIdRef.current = serverId;
    isRemoteServerRef.current = isRemoteServer;
  }, [isRemoteServer, serverId]);

  const queryClient = useQueryClient();
  const { t } = useTranslation();

  const { data: status, isLoading } = useQuery({
    queryKey: ["proxyStatus"],
    queryFn: () => invoke<ProxyStatus>("get_proxy_status"),
    refetchInterval: (query) => (query.state.data?.running ? 2000 : false),
    placeholderData: (previousData) => previousData,
  });

  const { data: takeoverStatus } = useQuery({
    queryKey: ["proxyTakeoverStatus"],
    queryFn: () => invoke<ProxyTakeoverStatus>("get_proxy_takeover_status"),
    placeholderData: (previousData) => previousData,
  });

  const { data: legacyTakeoverActive } = useQuery({
    queryKey: ["proxyLegacyTakeoverActive", serverId ?? "local"],
    queryFn: () => invoke<boolean>("is_live_takeover_active"),
    placeholderData: (previousData) => previousData,
  });

  const startProxyServerMutation = useMutation({
    mutationFn: () => {
      const currentServerId = serverIdRef.current;
      if (isRemoteServerRef.current) {
        return invoke<ProxyServerInfo>("start_proxy_with_takeover_for_server", {
          serverId: currentServerId,
        });
      }
      return invoke<ProxyServerInfo>("start_proxy_server");
    },
    onSuccess: (info) => {
      toast.success(
        t("proxy.server.started", {
          address: info.address,
          port: info.port,
          defaultValue: `代理服务已启动 - ${info.address}:${info.port}`,
        }),
        { closeButton: true },
      );
      queryClient.invalidateQueries({ queryKey: ["proxyStatus"] });
      queryClient.invalidateQueries({ queryKey: ["proxyTakeoverStatus"] });
      queryClient.invalidateQueries({
        queryKey: ["proxyLegacyTakeoverActive"],
      });
    },
    onError: (error: Error) => {
      const detail =
        extractErrorMessage(error) ||
        t("common.unknown", { defaultValue: "未知错误" });
      toast.error(
        t("proxy.server.startFailed", {
          defaultValue: `启动代理服务失败: ${detail}`,
        }),
      );
    },
  });

  const stopWithRestoreMutation = useMutation({
    mutationFn: () => {
      if (isRemoteServerRef.current) {
        return invoke("stop_proxy_with_restore_for_server");
      }
      return invoke("stop_proxy_with_restore");
    },
    onSuccess: () => {
      toast.success(
        t("proxy.stoppedWithRestore", {
          defaultValue: "代理服务已关闭，已恢复所有接管配置",
        }),
        { closeButton: true },
      );
      queryClient.invalidateQueries({ queryKey: ["proxyStatus"] });
      queryClient.invalidateQueries({ queryKey: ["proxyTakeoverStatus"] });
      queryClient.invalidateQueries({
        queryKey: ["proxyLegacyTakeoverActive"],
      });
      queryClient.removeQueries({ queryKey: ["providerHealth"] });
      queryClient.removeQueries({ queryKey: ["circuitBreakerStats"] });
    },
    onError: (error: Error) => {
      const detail =
        extractErrorMessage(error) ||
        t("common.unknown", { defaultValue: "未知错误" });
      toast.error(
        t("proxy.stopWithRestoreFailed", {
          defaultValue: `停止失败: ${detail}`,
        }),
      );
    },
  });

  const setTakeoverForAppMutation = useMutation({
    mutationFn: async ({
      appType,
      enabled,
    }: {
      appType: string;
      enabled: boolean;
    }) => {
      const currentServerId = serverIdRef.current;

      if (isRemoteServerRef.current) {
        if (enabled) {
          return invoke("start_proxy_with_takeover_for_server", {
            serverId: currentServerId,
          });
        }
        return invoke("stop_proxy_with_restore_for_server");
      }

      return invoke("set_proxy_takeover_for_app", { appType, enabled });
    },
    onSuccess: (_data, variables) => {
      if (isRemoteServerRef.current) {
        toast.success(
          variables.enabled
            ? t("proxy.startedWithTakeover", {
                defaultValue: "远程代理模式已启用",
              })
            : t("proxy.stoppedWithRestore", {
                defaultValue: "代理服务已关闭，已恢复所有接管配置",
              }),
          { closeButton: true },
        );
        queryClient.invalidateQueries({ queryKey: ["proxyStatus"] });
        queryClient.invalidateQueries({ queryKey: ["proxyTakeoverStatus"] });
        queryClient.invalidateQueries({
          queryKey: ["proxyLegacyTakeoverActive"],
        });
        return;
      }

      const appLabel =
        variables.appType === "claude"
          ? "Claude"
          : variables.appType === "codex"
            ? "Codex"
            : variables.appType === "gemini"
              ? "Gemini"
              : "OpenCode";

      toast.success(
        variables.enabled
          ? t("proxy.takeover.enabled", {
              app: appLabel,
              defaultValue: `已接管 ${appLabel} 配置（请求将走本地代理）`,
            })
          : t("proxy.takeover.disabled", {
              app: appLabel,
              defaultValue: `已恢复 ${appLabel} 配置`,
            }),
        { closeButton: true },
      );

      queryClient.invalidateQueries({ queryKey: ["proxyStatus"] });
      queryClient.invalidateQueries({ queryKey: ["proxyTakeoverStatus"] });
      queryClient.invalidateQueries({
        queryKey: ["proxyLegacyTakeoverActive"],
      });
    },
    onError: (error: Error) => {
      const detail =
        extractErrorMessage(error) ||
        t("common.unknown", { defaultValue: "未知错误" });
      toast.error(
        t("proxy.takeover.failed", {
          defaultValue: `操作失败: ${detail}`,
        }),
      );
    },
  });

  const switchProxyProviderMutation = useMutation({
    mutationFn: ({
      appType,
      providerId,
    }: {
      appType: string;
      providerId: string;
    }) => invoke("switch_proxy_provider", { appType, providerId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proxyStatus"] });
    },
    onError: (error: Error) => {
      const detail =
        extractErrorMessage(error) ||
        t("common.unknown", { defaultValue: "未知错误" });
      toast.error(
        t("proxy.switchFailed", {
          error: detail,
          defaultValue: `切换失败: ${detail}`,
        }),
      );
    },
  });

  const checkRunning = async () => {
    try {
      return await invoke<boolean>("is_proxy_running");
    } catch {
      return false;
    }
  };

  const checkTakeoverActive = async () => {
    try {
      return await invoke<boolean>("is_live_takeover_active");
    } catch {
      return false;
    }
  };

  const isTakeoverActive = isRemoteServer
    ? Boolean(legacyTakeoverActive)
    : Boolean(
        takeoverStatus?.claude || takeoverStatus?.codex || takeoverStatus?.gemini,
      );

  return {
    status,
    isLoading,
    isRunning: status?.running || false,
    takeoverStatus,
    isTakeoverActive,
    isRemoteServer,
    startProxyServer: startProxyServerMutation.mutateAsync,
    stopWithRestore: stopWithRestoreMutation.mutateAsync,
    setTakeoverForApp: setTakeoverForAppMutation.mutateAsync,
    switchProxyProvider: switchProxyProviderMutation.mutateAsync,
    checkRunning,
    checkTakeoverActive,
    isStarting: startProxyServerMutation.isPending,
    isStopping: stopWithRestoreMutation.isPending,
    isPending:
      startProxyServerMutation.isPending ||
      stopWithRestoreMutation.isPending ||
      setTakeoverForAppMutation.isPending,
  };
}
