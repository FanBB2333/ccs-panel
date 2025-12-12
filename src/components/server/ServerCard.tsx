import { Server, Laptop, Trash2, Settings, Wifi, WifiOff } from "lucide-react";
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
}

export function ServerCard({
  server,
  onClick,
  onEdit,
  onDelete,
}: ServerCardProps) {
  const { t } = useTranslation();

  const isLocal = server.isLocal;
  const isConnected = server.status === "connected";

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
        "group relative flex flex-col p-5 rounded-xl border transition-all duration-200 cursor-pointer",
        "bg-card hover:bg-accent/50",
        "border-border hover:border-primary/30",
        "hover:shadow-lg hover:shadow-primary/5",
        isConnected && "ring-1 ring-emerald-500/20"
      )}
      onClick={onClick}
    >
      {/* 顶部：图标和菜单 */}
      <div className="flex items-start justify-between mb-4">
        <div
          className={cn(
            "flex items-center justify-center w-12 h-12 rounded-xl",
            isLocal
              ? "bg-blue-500/10 text-blue-500"
              : "bg-orange-500/10 text-orange-500"
          )}
        >
          {isLocal ? (
            <Laptop className="w-6 h-6" />
          ) : (
            <Server className="w-6 h-6" />
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
      <h3 className="text-lg font-semibold text-foreground mb-1 truncate">
        {server.name}
      </h3>

      {/* 连接信息 */}
      <p className="text-sm text-muted-foreground mb-3 truncate">
        {isLocal
          ? t("server.localDescription", { defaultValue: "本机" })
          : server.sshConfig?.host || "SSH"}
      </p>

      {/* 状态指示器 */}
      <div className="flex items-center gap-2 mt-auto">
        {isConnected ? (
          <Wifi className={cn("w-4 h-4", statusColor)} />
        ) : (
          <WifiOff className={cn("w-4 h-4", statusColor)} />
        )}
        <span className={cn("text-sm", statusColor)}>{statusText}</span>
      </div>
    </div>
  );
}
