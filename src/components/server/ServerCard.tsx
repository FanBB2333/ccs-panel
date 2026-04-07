import { Server, Laptop, Trash2, Settings, Wifi, WifiOff, Loader2, Unplug } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { ManagedServer } from "@/types/server";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { MoreVertical } from "lucide-react";

interface ServerCardProps {
  server: ManagedServer;
  onClick: () => void;
  onEdit?: () => void;
  onDelete?: () => void;
  onDisconnect?: () => void;
  isConnecting?: boolean;
}

export function ServerCard({
  server,
  onClick,
  onEdit,
  onDelete,
  onDisconnect,
  isConnecting = false,
}: ServerCardProps) {
  const { t } = useTranslation();

  const isLocal = server.isLocal;
  const isConnected = server.status === "connected";
  const isCurrentConnecting = isConnecting || server.status === "connecting";

  const statusColor = {
    connected: "text-emerald-500",
    disconnected: "text-gray-400",
    connecting: "text-yellow-500",
    error: "text-red-500",
  }[server.status];

  const statusText = {
    connected: t("server.status.connected", { defaultValue: "已连接" }),
    disconnected: t("server.status.disconnected", { defaultValue: "未连接" }),
    connecting: t("server.status.connecting", { defaultValue: "连接中..." }),
    error: t("server.status.error", { defaultValue: "连接错误" }),
  }[server.status];

  return (
    <div
      className={cn(
        "group relative flex h-full min-h-[220px] flex-col rounded-2xl border p-6 transition-all duration-200 cursor-pointer",
        "bg-card hover:bg-accent/50",
        "border-border hover:border-primary/30",
        "hover:shadow-xl hover:shadow-primary/5",
        isConnected && "ring-1 ring-emerald-500/20",
      )}
      onClick={onClick}
    >
      {/* 顶部：图标和菜单 */}
      <div className="mb-5 flex items-start justify-between gap-4">
        <div
          className={cn(
            "flex h-14 w-14 items-center justify-center rounded-2xl",
            isLocal
              ? "bg-blue-500/10 text-blue-500"
              : "bg-orange-500/10 text-orange-500",
          )}
        >
          {isLocal ? (
            <Laptop className="h-7 w-7" />
          ) : (
            <Server className="h-7 w-7" />
          )}
        </div>

        {/* 操作菜单（仅非本地服务器显示） */}
        {!isLocal && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity"
                onClick={(e) => e.stopPropagation()}
              >
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {onEdit && (
                <DropdownMenuItem
                  onClick={(e) => {
                    e.stopPropagation();
                    onEdit();
                  }}
                >
                  <Settings className="h-4 w-4 mr-2" />
                  {t("common.edit", { defaultValue: "编辑" })}
                </DropdownMenuItem>
              )}
              {onDisconnect && isConnected && (
                <DropdownMenuItem
                  onClick={(e) => {
                    e.stopPropagation();
                    onDisconnect();
                  }}
                >
                  <Unplug className="h-4 w-4 mr-2" />
                  {t("server.disconnect", { defaultValue: "断开连接" })}
                </DropdownMenuItem>
              )}
              {onDelete && (
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete();
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  {t("common.delete", { defaultValue: "删除" })}
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {/* 服务器名称 */}
      <h3 className="mb-1 text-xl font-semibold text-foreground break-words">
        {isLocal
          ? t("server.localServer", { defaultValue: "本地服务器" })
          : server.name}
      </h3>

      {/* 连接信息 */}
      <p className="mb-4 text-sm text-muted-foreground break-all">
        {isLocal
          ? t("server.localDescription", { defaultValue: "本机" })
          : server.sshConfig?.host || "SSH"}
      </p>

      {/* 状态指示器 */}
      <div className="mt-auto flex items-center gap-2">
        {isCurrentConnecting ? (
          <Loader2 className={cn("w-4 h-4 animate-spin", statusColor)} />
        ) : isConnected ? (
          <Wifi className={cn("w-4 h-4", statusColor)} />
        ) : (
          <WifiOff className={cn("w-4 h-4", statusColor)} />
        )}
        <span className={cn("text-sm", statusColor)}>{statusText}</span>
      </div>
    </div>
  );
}
