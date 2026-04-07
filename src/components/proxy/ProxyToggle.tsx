/**
 * 代理模式切换开关组件
 */

import { Globe, Loader2, Radio } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useServer } from "@/contexts/ServerContext";
import { useProxyStatus } from "@/hooks/useProxyStatus";
import type { AppId } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Switch } from "@/components/ui/switch";

interface ProxyToggleProps {
  className?: string;
  activeApp: AppId;
}

export function ProxyToggle({ className, activeApp }: ProxyToggleProps) {
  const { t } = useTranslation();
  const { currentServer, currentServerId } = useServer();
  const {
    isPending,
    isRemoteServer,
    isRunning,
    isTakeoverActive,
    setTakeoverForApp,
    status,
    stopWithRestore,
    takeoverStatus,
  } = useProxyStatus({ serverId: currentServerId });

  const takeoverEnabled = isRemoteServer
    ? isTakeoverActive
    : Boolean(takeoverStatus?.[activeApp]);

  const handleToggle = async (checked: boolean) => {
    try {
      if (isRemoteServer && !checked) {
        await stopWithRestore();
        return;
      }

      await setTakeoverForApp({ appType: activeApp, enabled: checked });
    } catch (error) {
      console.error("[ProxyToggle] Toggle takeover failed:", error);
    }
  };

  const appLabel =
    activeApp === "claude"
      ? "Claude"
      : activeApp === "codex"
        ? "Codex"
        : activeApp === "gemini"
          ? "Gemini"
          : "OpenCode";

  const serverLabel = currentServer?.name || t("server.localServer");
  const tooltipText = isRemoteServer
    ? takeoverEnabled
      ? t("proxy.takeover.tooltip.active", {
          appLabel: serverLabel,
          address: status?.address,
          port: status?.port,
          defaultValue: `${serverLabel} 已接管 - ${status?.address}:${status?.port}`,
        })
      : t("proxy.takeover.tooltip.inactive", {
          appLabel: serverLabel,
          defaultValue: `通过 SSH 隧道接管 ${serverLabel} 的远程配置`,
        })
    : takeoverEnabled
      ? isRunning
        ? t("proxy.takeover.tooltip.active", {
            appLabel,
            address: status?.address,
            port: status?.port,
            defaultValue: `${appLabel} 已接管 - ${status?.address}:${status?.port}\n切换该应用供应商为热切换`,
          })
        : t("proxy.takeover.tooltip.broken", {
            appLabel,
            defaultValue: `${appLabel} 已接管，但代理服务未运行`,
          })
      : t("proxy.takeover.tooltip.inactive", {
          appLabel,
          defaultValue: `接管 ${appLabel} 的 Live 配置，让该应用请求走本地代理`,
        });

  return (
    <div
      className={cn(
        "flex items-center gap-1 px-1.5 h-8 rounded-lg bg-muted/50 transition-all",
        className,
      )}
      title={tooltipText}
    >
      {isPending ? (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      ) : isRemoteServer ? (
        <Globe
          className={cn(
            "h-4 w-4 transition-colors",
            takeoverEnabled
              ? "text-blue-500 animate-pulse"
              : "text-muted-foreground",
          )}
        />
      ) : (
        <Radio
          className={cn(
            "h-4 w-4 transition-colors",
            takeoverEnabled
              ? "text-emerald-500 animate-pulse"
              : "text-muted-foreground",
          )}
        />
      )}
      <Switch
        checked={takeoverEnabled}
        onCheckedChange={handleToggle}
        disabled={isPending}
      />
    </div>
  );
}
