import { useState, useEffect, useCallback } from "react";
import { Undo2, Save, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import type { RemoteConfigDirs } from "@/types/server";
import { sshApi } from "@/lib/api";

interface ServerDirectorySettingsProps {
  serverId: string;
  configDirs: RemoteConfigDirs;
  onConfigDirsChange: (dirs: RemoteConfigDirs) => void;
}

export function ServerDirectorySettings({
  serverId,
  configDirs,
  onConfigDirsChange,
}: ServerDirectorySettingsProps) {
  const { t } = useTranslation();
  const [isSaving, setIsSaving] = useState(false);

  // 本地状态管理所有目录
  const [localDirs, setLocalDirs] = useState<RemoteConfigDirs>({
    workingDir: configDirs.workingDir ?? "",
    claudeConfigDir: configDirs.claudeConfigDir ?? "",
    codexConfigDir: configDirs.codexConfigDir ?? "",
    geminiConfigDir: configDirs.geminiConfigDir ?? "",
  });

  // Sync local state when configDirs changes from external source
  useEffect(() => {
    setLocalDirs({
      workingDir: configDirs.workingDir ?? "",
      claudeConfigDir: configDirs.claudeConfigDir ?? "",
      codexConfigDir: configDirs.codexConfigDir ?? "",
      geminiConfigDir: configDirs.geminiConfigDir ?? "",
    });
  }, [configDirs]);

  const handleLocalChange = useCallback((key: keyof RemoteConfigDirs, value: string) => {
    setLocalDirs(prev => ({
      ...prev,
      [key]: value,
    }));
  }, []);

  const handleReset = useCallback((key: keyof RemoteConfigDirs) => {
    setLocalDirs(prev => ({
      ...prev,
      [key]: "",
    }));
  }, []);

  const handleSaveAll = useCallback(async () => {
    setIsSaving(true);
    try {
      const settings = {
        workingDir: localDirs.workingDir?.trim() || undefined,
        claudeConfigDir: localDirs.claudeConfigDir?.trim() || undefined,
        codexConfigDir: localDirs.codexConfigDir?.trim() || undefined,
        geminiConfigDir: localDirs.geminiConfigDir?.trim() || undefined,
      };

      await sshApi.saveServerSettings(serverId, settings);

      onConfigDirsChange(settings);
      toast.success(t("settings.serverSettingsSaved", { defaultValue: "服务器设置已保存" }));
    } catch (error) {
      console.error("[ServerDirectorySettings] Failed to save settings:", error);
      toast.error(t("settings.serverSettingsSaveFailed", { defaultValue: "保存服务器设置失败" }));
    } finally {
      setIsSaving(false);
    }
  }, [serverId, localDirs, onConfigDirsChange, t]);

  return (
    <section className="space-y-4">
      {/* 工作目录（CCS Panel 数据库路径） */}
      <div className="space-y-1">
        <h3 className="text-sm font-medium">
          {t("settings.workingDirectory", {
            defaultValue: "工作目录",
          })}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("settings.workingDirectoryDescription", {
            defaultValue:
              "设置远程服务器上 CCS Panel 数据库的存储路径。留空则使用默认路径 ~/.cc-switch/cc-switch.db",
          })}
        </p>
        <div className="flex items-center gap-2 mt-2">
          <Input
            value={localDirs.workingDir ?? ""}
            placeholder={t("settings.workingDirPlaceholder", {
              defaultValue: "~/.cc-switch/cc-switch.db (default)",
            })}
            className="text-xs"
            onChange={(e) => handleLocalChange("workingDir", e.target.value)}
          />
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={() => handleReset("workingDir")}
            title={t("settings.resetDefault")}
          >
            <Undo2 className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* 配置目录 */}
      <header className="space-y-1">
        <h3 className="text-sm font-medium">
          {t("settings.remoteConfigDirectory", {
            defaultValue: "远程配置目录",
          })}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("settings.remoteConfigDirectoryDescription", {
            defaultValue:
              "设置远程服务器上 Claude、Codex 和 Gemini 的配置文件路径。留空则使用默认路径。",
          })}
        </p>
      </header>

      <RemoteDirectoryInput
        label={t("settings.claudeConfigDir")}
        value={localDirs.claudeConfigDir}
        placeholder={t("settings.remotePlaceholderClaude", {
          defaultValue: "~/.claude (default)",
        })}
        onChange={(val) => handleLocalChange("claudeConfigDir", val ?? "")}
        onReset={() => handleReset("claudeConfigDir")}
      />

      <RemoteDirectoryInput
        label={t("settings.codexConfigDir")}
        value={localDirs.codexConfigDir}
        placeholder={t("settings.remotePlaceholderCodex", {
          defaultValue: "~/.codex (default)",
        })}
        onChange={(val) => handleLocalChange("codexConfigDir", val ?? "")}
        onReset={() => handleReset("codexConfigDir")}
      />

      <RemoteDirectoryInput
        label={t("settings.geminiConfigDir")}
        value={localDirs.geminiConfigDir}
        placeholder={t("settings.remotePlaceholderGemini", {
          defaultValue: "~/.gemini (default)",
        })}
        onChange={(val) => handleLocalChange("geminiConfigDir", val ?? "")}
        onReset={() => handleReset("geminiConfigDir")}
      />

      {/* 保存按钮 */}
      <div className="pt-2">
        <Button
          type="button"
          onClick={handleSaveAll}
          disabled={isSaving}
          className="w-full"
        >
          {isSaving ? (
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
          ) : (
            <Save className="h-4 w-4 mr-2" />
          )}
          {t("settings.saveServerSettings", { defaultValue: "保存服务器目录设置" })}
        </Button>
      </div>
    </section>
  );
}

interface RemoteDirectoryInputProps {
  label: string;
  value?: string;
  placeholder?: string;
  onChange: (value: string | undefined) => void;
  onReset: () => void;
}

function RemoteDirectoryInput({
  label,
  value,
  placeholder,
  onChange,
  onReset,
}: RemoteDirectoryInputProps) {
  const { t } = useTranslation();

  return (
    <div className="space-y-1.5">
      <p className="text-xs font-medium text-foreground">{label}</p>
      <div className="flex items-center gap-2">
        <Input
          value={value ?? ""}
          placeholder={placeholder}
          className="text-xs"
          onChange={(event) => onChange(event.target.value || undefined)}
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          onClick={onReset}
          title={t("settings.resetDefault")}
        >
          <Undo2 className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
