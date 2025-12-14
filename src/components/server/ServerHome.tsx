import { useState, useCallback, useEffect } from "react";
import { Plus, Settings } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useServer } from "@/contexts/ServerContext";
import { ServerCard } from "./ServerCard";
import { Button } from "@/components/ui/button";
import { ServerHomeSettings, type DisplayLanguage } from "./ServerHomeSettings";

const DISPLAY_LANGUAGE_KEY = "ccs-display-language";

// 映射 DisplayLanguage 到 i18n 语言代码
const displayLangToI18n: Record<DisplayLanguage, string> = {
  "zh": "zh",
  "en": "en",
};

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
  const { t, i18n } = useTranslation();
  const { servers, selectServer, isConnecting, disconnectFromServer } = useServer();

  // 设置对话框状态
  const [settingsOpen, setSettingsOpen] = useState(false);

  // 外部显示语言设置
  const [displayLanguage, setDisplayLanguage] = useState<DisplayLanguage>(() => {
    try {
      const saved = localStorage.getItem(DISPLAY_LANGUAGE_KEY);
      if (saved === "zh" || saved === "en") {
        return saved;
      }
    } catch {
      // localStorage 不可用
    }
    return "zh";
  });

  // 初始化时应用保存的语言设置
  useEffect(() => {
    const i18nLang = displayLangToI18n[displayLanguage];
    if (i18n.language !== i18nLang) {
      i18n.changeLanguage(i18nLang);
    }
  }, [displayLanguage, i18n]);

  // 保存外部显示语言设置
  const handleDisplayLanguageChange = useCallback((lang: DisplayLanguage) => {
    setDisplayLanguage(lang);
    try {
      localStorage.setItem(DISPLAY_LANGUAGE_KEY, lang);
    } catch {
      // localStorage 不可用
    }
  }, []);

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
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="icon"
            onClick={() => setSettingsOpen(true)}
            title={t("server.settings.title", { defaultValue: "服务器管理设置" })}
          >
            <Settings className="h-4 w-4" />
          </Button>
          <Button
            onClick={onAddServer}
            className="bg-orange-500 hover:bg-orange-600 dark:bg-orange-500 dark:hover:bg-orange-600 text-white shadow-lg shadow-orange-500/30 dark:shadow-orange-500/40"
          >
            <Plus className="h-4 w-4 mr-2" />
            {t("server.add", { defaultValue: "添加服务器" })}
          </Button>
        </div>
      </div>

      {/* 设置对话框 */}
      <ServerHomeSettings
        open={settingsOpen}
        onOpenChange={setSettingsOpen}
        displayLanguage={displayLanguage}
        onDisplayLanguageChange={handleDisplayLanguageChange}
      />

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
