/**
 * 服务器主页设置对话框
 * 用于设置外部显示内容的语言等配置
 */

import { useState, useEffect } from "react";
import { Settings } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type DisplayLanguage = "zh" | "en";

// 映射 DisplayLanguage 到 i18n 语言代码
const displayLangToI18n: Record<DisplayLanguage, string> = {
  "zh": "zh",
  "en": "en",
};

interface ServerHomeSettingsProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  displayLanguage: DisplayLanguage;
  onDisplayLanguageChange: (lang: DisplayLanguage) => void;
}

export function ServerHomeSettings({
  open,
  onOpenChange,
  displayLanguage,
  onDisplayLanguageChange,
}: ServerHomeSettingsProps) {
  const { t, i18n } = useTranslation();
  const [selectedLang, setSelectedLang] = useState<DisplayLanguage>(displayLanguage);

  // 同步外部值变化
  useEffect(() => {
    setSelectedLang(displayLanguage);
  }, [displayLanguage]);

  const handleSave = () => {
    onDisplayLanguageChange(selectedLang);
    // 切换 i18n 语言
    const i18nLang = displayLangToI18n[selectedLang];
    i18n.changeLanguage(i18nLang);
    toast.success(
      t("notifications.settingsSaved", { defaultValue: "设置已保存" })
    );
    onOpenChange(false);
  };

  const handleCancel = () => {
    setSelectedLang(displayLanguage);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            {t("server.settings.title", { defaultValue: "服务器管理设置" })}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <section className="space-y-3">
            <header className="space-y-1">
              <h3 className="text-sm font-medium">
                {t("server.settings.displayLanguage", { defaultValue: "外部显示语言" })}
              </h3>
              <p className="text-xs text-muted-foreground">
                {t("server.settings.displayLanguageHint", {
                  defaultValue: "控制对外展示内容（如错误信息、API 响应等）使用的语言",
                })}
              </p>
            </header>
            <div className="inline-flex gap-1 rounded-md border border-border bg-background p-1">
              <LanguageButton
                active={selectedLang === "zh"}
                onClick={() => setSelectedLang("zh")}
              >
                {t("server.settings.languageOptionSimplifiedChinese", { defaultValue: "简体中文" })}
              </LanguageButton>
              <LanguageButton
                active={selectedLang === "en"}
                onClick={() => setSelectedLang("en")}
              >
                {t("server.settings.languageOptionEnglish", { defaultValue: "English" })}
              </LanguageButton>
            </div>
          </section>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleCancel}>
            {t("common.cancel", { defaultValue: "取消" })}
          </Button>
          <Button onClick={handleSave}>
            {t("common.save", { defaultValue: "保存" })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface LanguageButtonProps {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}

function LanguageButton({ active, onClick, children }: LanguageButtonProps) {
  return (
    <Button
      type="button"
      onClick={onClick}
      size="sm"
      variant={active ? "default" : "ghost"}
      className={cn(
        "min-w-[80px]",
        active
          ? "shadow-sm"
          : "text-muted-foreground hover:text-foreground hover:bg-muted",
      )}
    >
      {children}
    </Button>
  );
}
