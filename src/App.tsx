import { useEffect, useMemo, useState, useRef } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { invoke } from "@tauri-apps/api/core";
import {
  Plus,
  Settings,
  ArrowLeft,
  // Bot, // TODO: Agents 功能开发中，暂时不需要
  Book,
  Wrench,
  Server,
  RefreshCw,
  Laptop,
} from "lucide-react";
import type { Provider } from "@/types";
import type { EnvConflict } from "@/types/env";
import type { ManagedServer } from "@/types/server";
import { useProvidersQuery } from "@/lib/query";
import {
  providersApi,
  settingsApi,
  type AppId,
  type ProviderSwitchEvent,
} from "@/lib/api";
import { checkAllEnvConflicts, checkEnvConflicts } from "@/lib/api/env";
import { useProviderActions } from "@/hooks/useProviderActions";
import { useProxyStatus } from "@/hooks/useProxyStatus";
import { useServer } from "@/contexts/ServerContext";
import { extractErrorMessage } from "@/utils/errorUtils";
import { cn } from "@/lib/utils";
import { AppSwitcher } from "@/components/AppSwitcher";
import { ProviderList } from "@/components/providers/ProviderList";
import { AddProviderDialog } from "@/components/providers/AddProviderDialog";
import { EditProviderDialog } from "@/components/providers/EditProviderDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { SettingsPage } from "@/components/settings/SettingsPage";
import { UpdateBadge } from "@/components/UpdateBadge";
import { EnvWarningBanner } from "@/components/env/EnvWarningBanner";
import { ProxyToggle } from "@/components/proxy/ProxyToggle";
import UsageScriptModal from "@/components/UsageScriptModal";
import UnifiedMcpPanel from "@/components/mcp/UnifiedMcpPanel";
import PromptPanel from "@/components/prompts/PromptPanel";
import { SkillsPage } from "@/components/skills/SkillsPage";
import { DeepLinkImportDialog } from "@/components/DeepLinkImportDialog";
import { AgentsPanel } from "@/components/agents/AgentsPanel";
import { Button } from "@/components/ui/button";
import { ServerHome, AddServerDialog } from "@/components/server";

type View = "providers" | "settings" | "prompts" | "skills" | "mcp" | "agents";

function App() {
  const { t } = useTranslation();

  // 服务器管理状态
  const {
    servers,
    isOnServerHome,
    currentServer,
    goBackToServerHome,
    addServer,
    updateServer,
    removeServer,
  } = useServer();
  const [isAddServerOpen, setIsAddServerOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<ManagedServer | null>(null);
  const [confirmDeleteServer, setConfirmDeleteServer] =
    useState<ManagedServer | null>(null);

  const [activeApp, setActiveApp] = useState<AppId>("claude");
  const [currentView, setCurrentView] = useState<View>("providers");
  const [isAddOpen, setIsAddOpen] = useState(false);

  const [editingProvider, setEditingProvider] = useState<Provider | null>(null);
  const [usageProvider, setUsageProvider] = useState<Provider | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<Provider | null>(null);
  const [envConflicts, setEnvConflicts] = useState<EnvConflict[]>([]);
  const [showEnvBanner, setShowEnvBanner] = useState(false);

  const promptPanelRef = useRef<any>(null);
  const mcpPanelRef = useRef<any>(null);
  const skillsPageRef = useRef<any>(null);
  const addActionButtonClass =
    "bg-orange-500 hover:bg-orange-600 dark:bg-orange-500 dark:hover:bg-orange-600 text-white shadow-lg shadow-orange-500/30 dark:shadow-orange-500/40 rounded-full w-8 h-8";

  // 获取代理服务状态
  const { isRunning: isProxyRunning, isTakeoverActive } = useProxyStatus();

  // 获取供应商列表，当代理服务运行时自动刷新
  // 根据当前服务器决定是从本地还是远程加载
  const { data, isLoading, refetch } = useProvidersQuery(activeApp, {
    isProxyRunning,
    server: currentServer,
  });
  const providers = useMemo(() => data?.providers ?? {}, [data]);
  const currentProviderId = data?.currentProviderId ?? "";
  // Skills 功能仅支持 Claude 和 Codex
  const hasSkillsSupport = activeApp === "claude" || activeApp === "codex";

  // 🎯 使用 useProviderActions Hook 统一管理所有 Provider 操作
  const {
    addProvider,
    updateProvider,
    switchProvider,
    deleteProvider,
    saveUsageScript,
  } = useProviderActions(activeApp);

  // 监听来自托盘菜单的切换事件
  useEffect(() => {
    let unsubscribe: (() => void) | undefined;

    const setupListener = async () => {
      try {
        unsubscribe = await providersApi.onSwitched(
          async (event: ProviderSwitchEvent) => {
            if (event.appType === activeApp) {
              await refetch();
            }
          },
        );
      } catch (error) {
        console.error("[App] Failed to subscribe provider switch event", error);
      }
    };

    setupListener();
    return () => {
      unsubscribe?.();
    };
  }, [activeApp, refetch]);

  // 应用启动时检测所有应用的环境变量冲突
  useEffect(() => {
    const checkEnvOnStartup = async () => {
      try {
        const allConflicts = await checkAllEnvConflicts();
        const flatConflicts = Object.values(allConflicts).flat();

        if (flatConflicts.length > 0) {
          setEnvConflicts(flatConflicts);
          const dismissed = sessionStorage.getItem("env_banner_dismissed");
          if (!dismissed) {
            setShowEnvBanner(true);
          }
        }
      } catch (error) {
        console.error(
          "[App] Failed to check environment conflicts on startup:",
          error,
        );
      }
    };

    checkEnvOnStartup();
  }, []);

  // 应用启动时检查是否刚完成了配置迁移
  useEffect(() => {
    const checkMigration = async () => {
      try {
        const migrated = await invoke<boolean>("get_migration_result");
        if (migrated) {
          toast.success(
            t("migration.success", { defaultValue: "配置迁移成功" }),
          );
        }
      } catch (error) {
        console.error("[App] Failed to check migration result:", error);
      }
    };

    checkMigration();
  }, [t]);

  // 切换应用时检测当前应用的环境变量冲突
  useEffect(() => {
    const checkEnvOnSwitch = async () => {
      try {
        const conflicts = await checkEnvConflicts(activeApp);

        if (conflicts.length > 0) {
          // 合并新检测到的冲突
          setEnvConflicts((prev) => {
            const existingKeys = new Set(
              prev.map((c) => `${c.varName}:${c.sourcePath}`),
            );
            const newConflicts = conflicts.filter(
              (c) => !existingKeys.has(`${c.varName}:${c.sourcePath}`),
            );
            return [...prev, ...newConflicts];
          });
          const dismissed = sessionStorage.getItem("env_banner_dismissed");
          if (!dismissed) {
            setShowEnvBanner(true);
          }
        }
      } catch (error) {
        console.error(
          "[App] Failed to check environment conflicts on app switch:",
          error,
        );
      }
    };

    checkEnvOnSwitch();
  }, [activeApp]);

  // 打开网站链接
  const handleOpenWebsite = async (url: string) => {
    try {
      await settingsApi.openExternal(url);
    } catch (error) {
      const detail =
        extractErrorMessage(error) ||
        t("notifications.openLinkFailed", {
          defaultValue: "链接打开失败",
        });
      toast.error(detail);
    }
  };

  // 编辑供应商
  const handleEditProvider = async (provider: Provider) => {
    await updateProvider(provider);
    setEditingProvider(null);
  };

  // 确认删除供应商
  const handleConfirmDelete = async () => {
    if (!confirmDelete) return;
    await deleteProvider(confirmDelete.id);
    setConfirmDelete(null);
  };

  // 复制供应商
  const handleDuplicateProvider = async (provider: Provider) => {
    // 1️⃣ 计算新的 sortIndex：如果原供应商有 sortIndex，则复制它
    const newSortIndex =
      provider.sortIndex !== undefined ? provider.sortIndex + 1 : undefined;

    const duplicatedProvider: Omit<Provider, "id" | "createdAt"> = {
      name: `${provider.name} copy`,
      settingsConfig: JSON.parse(JSON.stringify(provider.settingsConfig)), // 深拷贝
      websiteUrl: provider.websiteUrl,
      category: provider.category,
      sortIndex: newSortIndex, // 复制原 sortIndex + 1
      meta: provider.meta
        ? JSON.parse(JSON.stringify(provider.meta))
        : undefined, // 深拷贝
      icon: provider.icon,
      iconColor: provider.iconColor,
    };

    // 2️⃣ 如果原供应商有 sortIndex，需要将后续所有供应商的 sortIndex +1
    if (provider.sortIndex !== undefined) {
      const updates = Object.values(providers)
        .filter(
          (p) =>
            p.sortIndex !== undefined &&
            p.sortIndex >= newSortIndex! &&
            p.id !== provider.id,
        )
        .map((p) => ({
          id: p.id,
          sortIndex: p.sortIndex! + 1,
        }));

      // 先更新现有供应商的 sortIndex，为新供应商腾出位置
      if (updates.length > 0) {
        try {
          await providersApi.updateSortOrder(updates, activeApp);
        } catch (error) {
          console.error("[App] Failed to update sort order", error);
          toast.error(
            t("provider.sortUpdateFailed", {
              defaultValue: "排序更新失败",
            }),
          );
          return; // 如果排序更新失败，不继续添加
        }
      }
    }

    // 3️⃣ 添加复制的供应商
    await addProvider(duplicatedProvider);
  };

  // 导入配置成功后刷新
  const handleImportSuccess = async () => {
    await refetch();
    try {
      await providersApi.updateTrayMenu();
    } catch (error) {
      console.error("[App] Failed to refresh tray menu", error);
    }
  };

  const renderContent = () => {
    switch (currentView) {
      case "settings":
        return (
          <SettingsPage
            open={true}
            onOpenChange={() => setCurrentView("providers")}
            onImportSuccess={handleImportSuccess}
          />
        );
      case "prompts":
        return (
          <PromptPanel
            ref={promptPanelRef}
            open={true}
            onOpenChange={() => setCurrentView("providers")}
            appId={activeApp}
          />
        );
      case "skills":
        return (
          <SkillsPage
            ref={skillsPageRef}
            onClose={() => setCurrentView("providers")}
            initialApp={activeApp}
          />
        );
      case "mcp":
        return (
          <UnifiedMcpPanel
            ref={mcpPanelRef}
            onOpenChange={() => setCurrentView("providers")}
          />
        );
      case "agents":
        return <AgentsPanel onOpenChange={() => setCurrentView("providers")} />;
      default:
        return (
          <div className="mx-auto max-w-[56rem] px-5 flex flex-col h-[calc(100vh-8rem)] overflow-hidden">
            {/* 独立滚动容器 - 解决 Linux/Ubuntu 下 DndContext 与滚轮事件冲突 */}
            <div className="flex-1 overflow-y-auto overflow-x-hidden pb-12 px-1">
              <div className="space-y-4">
                <ProviderList
                  providers={providers}
                  currentProviderId={currentProviderId}
                  appId={activeApp}
                  isLoading={isLoading}
                  isProxyRunning={isProxyRunning}
                  isProxyTakeover={isProxyRunning && isTakeoverActive}
                  onSwitch={switchProvider}
                  onEdit={setEditingProvider}
                  onDelete={setConfirmDelete}
                  onDuplicate={handleDuplicateProvider}
                  onConfigureUsage={setUsageProvider}
                  onOpenWebsite={handleOpenWebsite}
                  onCreate={() => setIsAddOpen(true)}
                />
              </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div
      className="flex min-h-screen flex-col bg-background text-foreground selection:bg-primary/30"
      style={{ overflowX: "hidden" }}
    >
      {/* 全局拖拽区域（顶部 4px），避免上边框无法拖动 */}
      <div
        className="fixed top-0 left-0 right-0 h-4 z-[60]"
        data-tauri-drag-region
        style={{ WebkitAppRegion: "drag" } as any}
      />
      {/* 环境变量警告横幅 */}
      {showEnvBanner && envConflicts.length > 0 && (
        <EnvWarningBanner
          conflicts={envConflicts}
          onDismiss={() => {
            setShowEnvBanner(false);
            sessionStorage.setItem("env_banner_dismissed", "true");
          }}
          onDeleted={async () => {
            // 删除后重新检测
            try {
              const allConflicts = await checkAllEnvConflicts();
              const flatConflicts = Object.values(allConflicts).flat();
              setEnvConflicts(flatConflicts);
              if (flatConflicts.length === 0) {
                setShowEnvBanner(false);
              }
            } catch (error) {
              console.error(
                "[App] Failed to re-check conflicts after deletion:",
                error,
              );
            }
          }}
        />
      )}

      <header
        className="fixed top-0 z-50 w-full py-3 bg-background/80 backdrop-blur-md transition-all duration-300"
        data-tauri-drag-region
        style={{ WebkitAppRegion: "drag" } as any}
      >
        <div className="h-4 w-full" aria-hidden data-tauri-drag-region />
        <div
          className="mx-auto max-w-[56rem] px-6 flex flex-wrap items-center justify-between gap-2"
          data-tauri-drag-region
          style={{ WebkitAppRegion: "drag" } as any}
        >
          <div
            className="flex items-center gap-1"
            style={{ WebkitAppRegion: "no-drag" } as any}
          >
            {/* 一级页面：服务器管理主页 */}
            {isOnServerHome ? (
              <>
                <div className="flex items-center gap-2">
                  <a
                    href="https://github.com/farion1231/cc-switch"
                    target="_blank"
                    rel="noreferrer"
                    className="text-xl font-semibold transition-colors text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300"
                  >
                    CCS Panel
                  </a>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setCurrentView("settings")}
                    title={t("common.settings")}
                    className="hover:bg-black/5 dark:hover:bg-white/5"
                  >
                    <Settings className="h-4 w-4" />
                  </Button>
                </div>
                <UpdateBadge onClick={() => setCurrentView("settings")} />
              </>
            ) : currentView !== "providers" ? (
              /* 二级页面的子页面（settings/prompts等） */
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setCurrentView("providers")}
                  className="mr-2 rounded-lg"
                >
                  <ArrowLeft className="h-4 w-4" />
                </Button>
                <h1 className="text-lg font-semibold">
                  {currentView === "settings" && t("settings.title")}
                  {currentView === "prompts" &&
                    t("prompts.title", { appName: t(`apps.${activeApp}`) })}
                  {currentView === "skills" && t("skills.title")}
                  {currentView === "mcp" && t("mcp.unifiedPanel.title")}
                  {currentView === "agents" && t("agents.title")}
                </h1>
              </div>
            ) : (
              /* 二级页面：供应商管理 - 显示当前服务器信息和返回按钮 */
              <>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={goBackToServerHome}
                    className="mr-2 rounded-lg"
                    title={t("server.backToList", { defaultValue: "返回服务器列表" })}
                  >
                    <ArrowLeft className="h-4 w-4" />
                  </Button>
                  <div className="flex items-center gap-2">
                    {currentServer?.isLocal ? (
                      <Laptop className="h-4 w-4 text-blue-500" />
                    ) : (
                      <Server className="h-4 w-4 text-orange-500" />
                    )}
                    <span className="text-sm font-medium text-muted-foreground">
                      {currentServer?.name || t("server.unknown", { defaultValue: "未知服务器" })}
                    </span>
                  </div>
                  <a
                    href="https://github.com/farion1231/cc-switch"
                    target="_blank"
                    rel="noreferrer"
                    className={cn(
                      "text-xl font-semibold transition-colors ml-2",
                      isProxyRunning && isTakeoverActive
                        ? "text-emerald-500 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300"
                        : "text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300"
                    )}
                  >
                    CC Switch
                  </a>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setCurrentView("settings")}
                    title={t("common.settings")}
                    className="hover:bg-black/5 dark:hover:bg-white/5"
                  >
                    <Settings className="h-4 w-4" />
                  </Button>
                </div>
                <UpdateBadge onClick={() => setCurrentView("settings")} />
              </>
            )}
          </div>

          <div
            className="flex items-center gap-2"
            style={{ WebkitAppRegion: "no-drag" } as any}
          >
            {currentView === "prompts" && (
              <Button
                size="icon"
                onClick={() => promptPanelRef.current?.openAdd()}
                className={addActionButtonClass}
                title={t("prompts.add")}
              >
                <Plus className="h-5 w-5" />
              </Button>
            )}
            {currentView === "mcp" && (
              <Button
                size="icon"
                onClick={() => mcpPanelRef.current?.openAdd()}
                className={addActionButtonClass}
                title={t("mcp.unifiedPanel.addServer")}
              >
                <Plus className="h-5 w-5" />
              </Button>
            )}
            {currentView === "skills" && (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => skillsPageRef.current?.refresh()}
                  className="hover:bg-black/5 dark:hover:bg-white/5"
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  {t("skills.refresh")}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => skillsPageRef.current?.openRepoManager()}
                  className="hover:bg-black/5 dark:hover:bg-white/5"
                >
                  <Settings className="h-4 w-4 mr-2" />
                  {t("skills.repoManager")}
                </Button>
              </>
            )}
            {currentView === "providers" && !isOnServerHome && (
              <>
                <ProxyToggle />

                <AppSwitcher activeApp={activeApp} onSwitch={setActiveApp} />

                <div className="bg-muted p-1 rounded-xl flex items-center gap-1">
                  {hasSkillsSupport && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCurrentView("skills")}
                      className="text-muted-foreground hover:text-foreground hover:bg-black/5 dark:hover:bg-white/5"
                      title={t("skills.manage")}
                    >
                      <Wrench className="h-4 w-4" />
                    </Button>
                  )}
                  {/* TODO: Agents 功能开发中，暂时隐藏入口 */}
                  {/* {isClaudeApp && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCurrentView("agents")}
                      className="text-muted-foreground hover:text-foreground hover:bg-black/5 dark:hover:bg-white/5"
                      title="Agents"
                    >
                      <Bot className="h-4 w-4" />
                    </Button>
                  )} */}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setCurrentView("prompts")}
                    className="text-muted-foreground hover:text-foreground hover:bg-black/5 dark:hover:bg-white/5"
                    title={t("prompts.manage")}
                  >
                    <Book className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setCurrentView("mcp")}
                    className="text-muted-foreground hover:text-foreground hover:bg-black/5 dark:hover:bg-white/5"
                    title={t("mcp.title")}
                  >
                    <Server className="h-4 w-4" />
                  </Button>
                </div>

                <Button
                  onClick={() => setIsAddOpen(true)}
                  size="icon"
                  className={`ml-2 ${addActionButtonClass}`}
                >
                  <Plus className="h-5 w-5" />
                </Button>
              </>
            )}
          </div>
        </div>
      </header>

      <main
        className={`flex-1 overflow-y-auto pb-12 animate-fade-in scroll-overlay ${
          isOnServerHome ? "pt-24" : currentView === "providers" ? "pt-28" : "pt-20"
        }`}
        style={{ overflowX: "hidden" }}
      >
        {isOnServerHome ? (
          <ServerHome
            onAddServer={() => setIsAddServerOpen(true)}
            onEditServer={(serverId) => {
              const server = servers[serverId];
              if (server) {
                setEditingServer(server);
                setIsAddServerOpen(true);
              }
            }}
            onDeleteServer={(serverId) => {
              const server = servers[serverId];
              if (server) {
                setConfirmDeleteServer(server);
              }
            }}
          />
        ) : (
          renderContent()
        )}
      </main>

      <AddProviderDialog
        open={isAddOpen}
        onOpenChange={setIsAddOpen}
        appId={activeApp}
        onSubmit={addProvider}
      />

      <EditProviderDialog
        open={Boolean(editingProvider)}
        provider={editingProvider}
        onOpenChange={(open) => {
          if (!open) {
            setEditingProvider(null);
          }
        }}
        onSubmit={handleEditProvider}
        appId={activeApp}
      />

      {usageProvider && (
        <UsageScriptModal
          provider={usageProvider}
          appId={activeApp}
          isOpen={Boolean(usageProvider)}
          onClose={() => setUsageProvider(null)}
          onSave={(script) => {
            void saveUsageScript(usageProvider, script);
          }}
        />
      )}

      <ConfirmDialog
        isOpen={Boolean(confirmDelete)}
        title={t("confirm.deleteProvider")}
        message={
          confirmDelete
            ? t("confirm.deleteProviderMessage", {
                name: confirmDelete.name,
              })
            : ""
        }
        onConfirm={() => void handleConfirmDelete()}
        onCancel={() => setConfirmDelete(null)}
      />

      {/* 服务器管理相关对话框 */}
      <AddServerDialog
        open={isAddServerOpen}
        onOpenChange={(open) => {
          setIsAddServerOpen(open);
          if (!open) {
            setEditingServer(null);
          }
        }}
        editingServer={editingServer}
        onSubmit={(serverData) => {
          if (editingServer) {
            // 编辑模式：更新服务器
            updateServer({
              ...serverData,
              id: editingServer.id,
              createdAt: editingServer.createdAt,
            });
          } else {
            // 新建模式：添加服务器
            addServer(serverData);
          }
          setEditingServer(null);
        }}
      />

      <ConfirmDialog
        isOpen={Boolean(confirmDeleteServer)}
        title={t("server.confirmDelete", { defaultValue: "删除服务器" })}
        message={
          confirmDeleteServer
            ? t("server.confirmDeleteMessage", {
                defaultValue: `确定要删除服务器 "${confirmDeleteServer.name}" 吗？`,
                name: confirmDeleteServer.name,
              })
            : ""
        }
        onConfirm={() => {
          if (confirmDeleteServer) {
            removeServer(confirmDeleteServer.id);
            setConfirmDeleteServer(null);
          }
        }}
        onCancel={() => setConfirmDeleteServer(null)}
      />

      <DeepLinkImportDialog />
    </div>
  );
}

export default App;
