import { Undo2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useTranslation } from "react-i18next";
import type { RemoteConfigDirs } from "@/types/server";

interface ServerDirectorySettingsProps {
  configDirs: RemoteConfigDirs;
  onConfigDirsChange: (dirs: RemoteConfigDirs) => void;
}

export function ServerDirectorySettings({
  configDirs,
  onConfigDirsChange,
}: ServerDirectorySettingsProps) {
  const { t } = useTranslation();

  const handleChange = (
    key: keyof RemoteConfigDirs,
    value: string | undefined
  ) => {
    onConfigDirsChange({
      ...configDirs,
      [key]: value?.trim() || undefined,
    });
  };

  const handleReset = (key: keyof RemoteConfigDirs) => {
    onConfigDirsChange({
      ...configDirs,
      [key]: undefined,
    });
  };

  return (
    <section className="space-y-4">
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
        value={configDirs.claudeConfigDir}
        placeholder={t("settings.remotePlaceholderClaude", {
          defaultValue: "~/.claude(default)",
        })}
        onChange={(val) => handleChange("claudeConfigDir", val)}
        onReset={() => handleReset("claudeConfigDir")}
      />

      <RemoteDirectoryInput
        label={t("settings.codexConfigDir")}
        value={configDirs.codexConfigDir}
        placeholder={t("settings.remotePlaceholderCodex", {
          defaultValue: "~/.codex(default)",
        })}
        onChange={(val) => handleChange("codexConfigDir", val)}
        onReset={() => handleReset("codexConfigDir")}
      />

      <RemoteDirectoryInput
        label={t("settings.geminiConfigDir")}
        value={configDirs.geminiConfigDir}
        placeholder={t("settings.remotePlaceholderGemini", {
          defaultValue: "~/.gemini(default)",
        })}
        onChange={(val) => handleChange("geminiConfigDir", val)}
        onReset={() => handleReset("geminiConfigDir")}
      />
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
