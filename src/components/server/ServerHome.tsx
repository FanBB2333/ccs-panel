import { Plus } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useServer } from "@/contexts/ServerContext";
import { ServerCard } from "./ServerCard";
import { Button } from "@/components/ui/button";

interface ServerHomeProps {
  onAddServer: () => void;
  onEditServer?: (serverId: string) => void;
  onDeleteServer?: (serverId: string) => void;
}

export function ServerHome({
  onAddServer,
  onEditServer,
  onDeleteServer,
}: ServerHomeProps) {
  const { t } = useTranslation();
  const { servers, selectServer, isConnecting, disconnectFromServer } = useServer();

  // 将服务器转换为数组并排序（本地服务器在最前面）
  const serverList = Object.values(servers).sort((a, b) => {
    if (a.isLocal) return -1;
    if (b.isLocal) return 1;
    return a.createdAt - b.createdAt;
  });

  return (
    <div className="mx-auto max-w-[56rem] px-5 flex flex-col h-[calc(100vh-8rem)] overflow-hidden">
      {/* 页面标题 */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">
            {t("server.title", { defaultValue: "服务器管理" })}
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {t("server.subtitle", {
              defaultValue: "选择一个服务器来管理其配置",
            })}
          </p>
        </div>
        <Button
          onClick={onAddServer}
          className="bg-orange-500 hover:bg-orange-600 dark:bg-orange-500 dark:hover:bg-orange-600 text-white shadow-lg shadow-orange-500/30 dark:shadow-orange-500/40"
        >
          <Plus className="h-4 w-4 mr-2" />
          {t("server.add", { defaultValue: "添加服务器" })}
        </Button>
      </div>

      {/* 服务器卡片网格 */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden pb-12 px-1">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 animate-slide-up">
          {serverList.map((server) => (
            <ServerCard
              key={server.id}
              server={server}
              onClick={() => selectServer(server.id)}
              onEdit={
                !server.isLocal && onEditServer
                  ? () => onEditServer(server.id)
                  : undefined
              }
              onDelete={
                !server.isLocal && onDeleteServer
                  ? () => onDeleteServer(server.id)
                  : undefined
              }
              onDisconnect={
                !server.isLocal
                  ? () => disconnectFromServer(server.id)
                  : undefined
              }
              isConnecting={isConnecting && server.status === "connecting"}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
