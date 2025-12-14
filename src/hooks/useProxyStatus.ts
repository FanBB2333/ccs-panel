/**
 * 代理服务状态管理 Hook
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { useRef, useEffect } from "react";
import type { ProxyStatus, ProxyServerInfo } from "@/types/proxy";
import { extractErrorMessage } from "@/utils/errorUtils";

interface UseProxyStatusOptions {
  /**
   * 服务器 ID，null 或 "local" 表示本地服务器，其他值表示远程服务器
   */
  serverId?: string | null;
}

/**
 * 代理服务状态管理
 * @param options.serverId - 服务器 ID，用于区分本地模式和远程服务器模式
 */
export function useProxyStatus(options: UseProxyStatusOptions = {}) {
  const { serverId } = options;
  // 判断是否为远程服务器（serverId 存在且不为 "local"）
  const isRemoteServer = serverId != null && serverId !== "local";

  // 使用 ref 来保存最新的 serverId，避免闭包捕获旧值
  const serverIdRef = useRef(serverId);
  const isRemoteServerRef = useRef(isRemoteServer);

  // 每次渲染时更新 ref
  useEffect(() => {
    serverIdRef.current = serverId;
    isRemoteServerRef.current = isRemoteServer;
  });

  const queryClient = useQueryClient();
  const { t } = useTranslation();

  // 查询状态（自动轮询）
  const { data: status, isLoading } = useQuery({
    queryKey: ["proxyStatus"],
    queryFn: () => invoke<ProxyStatus>("get_proxy_status"),
    // 仅在服务运行时轮询
    refetchInterval: (query) => (query.state.data?.running ? 2000 : false),
    // 保持之前的数据，避免闪烁
    placeholderData: (previousData) => previousData,
  });

  // 查询接管状态
  const { data: isTakeoverActive } = useQuery({
    queryKey: ["proxyTakeoverActive"],
    queryFn: () => invoke<boolean>("is_live_takeover_active"),
  });

  // 启动服务器（带 Live 配置接管）
  // 根据是否为远程服务器调用不同的后端命令
  const startWithTakeoverMutation = useMutation({
    mutationFn: () => {
      // 使用 ref 获取最新的值，避免闭包捕获旧值
      const currentServerId = serverIdRef.current;
      const currentIsRemoteServer = isRemoteServerRef.current;

      console.log("[useProxyStatus] startWithTakeover called, serverId:", currentServerId, "isRemoteServer:", currentIsRemoteServer);
      if (currentIsRemoteServer) {
        // 远程服务器模式：启动本地代理 + SSH 端口转发 + 修改远程配置
        console.log("[useProxyStatus] Calling start_proxy_with_takeover_for_server with serverId:", currentServerId);
        return invoke<ProxyServerInfo>("start_proxy_with_takeover_for_server", {
          serverId: currentServerId,  // camelCase for Tauri
        });
      } else {
        // 本地模式
        console.log("[useProxyStatus] Calling start_proxy_with_takeover (local mode)");
        return invoke<ProxyServerInfo>("start_proxy_with_takeover");
      }
    },
    onSuccess: (info) => {
      const modeText = isRemoteServerRef.current ? "远程" : "本地";
      toast.success(
        t("proxy.startedWithTakeover", {
          defaultValue: `${modeText}代理模式已启用 - ${info.address}:${info.port}`,
        }),
      );
      queryClient.invalidateQueries({ queryKey: ["proxyStatus"] });
      queryClient.invalidateQueries({ queryKey: ["proxyTakeoverActive"] });
    },
    onError: (error: Error) => {
      const detail = extractErrorMessage(error) || "未知错误";
      toast.error(
        t("proxy.startWithTakeoverFailed", {
          defaultValue: `启动失败: ${detail}`,
        }),
      );
    },
  });

  // 停止服务器（恢复 Live 配置）
  // 根据是否为远程服务器调用不同的后端命令
  const stopWithRestoreMutation = useMutation({
    mutationFn: () => {
      // 使用 ref 获取最新的值，避免闭包捕获旧值
      const currentIsRemoteServer = isRemoteServerRef.current;

      if (currentIsRemoteServer) {
        // 远程服务器模式：恢复远程配置 + 停止 SSH 端口转发 + 停止本地代理
        return invoke("stop_proxy_with_restore_for_server");
      } else {
        // 本地模式
        return invoke("stop_proxy_with_restore");
      }
    },
    onSuccess: () => {
      toast.success(
        t("proxy.stoppedWithRestore", {
          defaultValue: "代理模式已关闭，配置已恢复",
        }),
      );
      queryClient.invalidateQueries({ queryKey: ["proxyStatus"] });
      queryClient.invalidateQueries({ queryKey: ["proxyTakeoverActive"] });
    },
    onError: (error: Error) => {
      const detail = extractErrorMessage(error) || "未知错误";
      toast.error(
        t("proxy.stopWithRestoreFailed", {
          defaultValue: `停止失败: ${detail}`,
        }),
      );
    },
  });

  // 代理模式切换供应商（热切换）
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
      const detail = extractErrorMessage(error) || "未知错误";
      toast.error(`切换失败: ${detail}`);
    },
  });

  // 检查是否运行中
  const checkRunning = async () => {
    try {
      return await invoke<boolean>("is_proxy_running");
    } catch {
      return false;
    }
  };

  // 检查接管状态
  const checkTakeoverActive = async () => {
    try {
      return await invoke<boolean>("is_live_takeover_active");
    } catch {
      return false;
    }
  };

  return {
    status,
    isLoading,
    isRunning: status?.running || false,
    isTakeoverActive: isTakeoverActive || false,
    isRemoteServer,

    // 启动/停止（接管模式）
    startWithTakeover: startWithTakeoverMutation.mutateAsync,
    stopWithRestore: stopWithRestoreMutation.mutateAsync,

    // 代理模式下切换供应商
    switchProxyProvider: switchProxyProviderMutation.mutateAsync,

    // 状态检查
    checkRunning,
    checkTakeoverActive,

    // 加载状态
    isStarting: startWithTakeoverMutation.isPending,
    isStopping: stopWithRestoreMutation.isPending,
    isPending:
      startWithTakeoverMutation.isPending || stopWithRestoreMutation.isPending,
  };
}
