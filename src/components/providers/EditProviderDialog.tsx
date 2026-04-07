import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Save } from "lucide-react";
import { FullScreenPanel } from "@/components/common/FullScreenPanel";
import {
  ProviderForm,
  type ProviderFormValues,
} from "@/components/providers/forms/ProviderForm";
import { Button } from "@/components/ui/button";
import { useServer } from "@/contexts/ServerContext";
import { openclawApi, providersApi, sshApi, vscodeApi, type AppId } from "@/lib/api";
import type { Provider } from "@/types";

interface EditProviderDialogProps {
  open: boolean;
  provider: Provider | null;
  onOpenChange: (open: boolean) => void;
  onSubmit: (provider: Provider) => Promise<void> | void;
  appId: AppId;
  isProxyTakeover?: boolean;
}

export function EditProviderDialog({
  open,
  provider,
  onOpenChange,
  onSubmit,
  appId,
  isProxyTakeover = false,
}: EditProviderDialogProps) {
  const { t } = useTranslation();
  const { currentServer } = useServer();
  const [isFormSubmitting, setIsFormSubmitting] = useState(false);
  const [liveSettings, setLiveSettings] = useState<Record<string, unknown> | null>(null);
  const [hasLoadedLive, setHasLoadedLive] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      if (!open || !provider) {
        setLiveSettings(null);
        setHasLoadedLive(false);
        return;
      }

      if (hasLoadedLive) {
        return;
      }

      if (isProxyTakeover || appId === "opencode") {
        if (!cancelled) {
          setLiveSettings(null);
          setHasLoadedLive(true);
        }
        return;
      }

      if (appId === "openclaw") {
        try {
          const live = await openclawApi.getLiveProvider(provider.id);
          if (!cancelled && live && typeof live === "object") {
            setLiveSettings(live);
          } else if (!cancelled) {
            setLiveSettings(null);
          }
        } catch {
          if (!cancelled) {
            setLiveSettings(null);
          }
        } finally {
          if (!cancelled) {
            setHasLoadedLive(true);
          }
        }
        return;
      }

      try {
        const isRemote =
          currentServer &&
          !currentServer.isLocal &&
          currentServer.connectionType === "ssh";

        if (isRemote) {
          const remoteConfig = await sshApi.readRemoteConfig(
            currentServer.id,
            appId,
          );
          const currentId = remoteConfig.current_provider_id;
          if (currentId && provider.id === currentId) {
            const live = await sshApi.readRemoteLiveProviderSettings(
              currentServer.id,
              appId,
            );
            if (!cancelled && live && typeof live === "object") {
              setLiveSettings(live as Record<string, unknown>);
            }
          } else if (!cancelled) {
            setLiveSettings(null);
          }
          return;
        }

        const currentId = await providersApi.getCurrent(appId);
        if (currentId && provider.id === currentId) {
          const live = await vscodeApi.getLiveProviderSettings(appId);
          if (!cancelled && live && typeof live === "object") {
            setLiveSettings(live as Record<string, unknown>);
          }
        } else if (!cancelled) {
          setLiveSettings(null);
        }
      } catch {
        if (!cancelled) {
          setLiveSettings(null);
        }
      } finally {
        if (!cancelled) {
          setHasLoadedLive(true);
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [appId, currentServer, hasLoadedLive, isProxyTakeover, open, provider?.id]);

  const initialSettingsConfig = useMemo(() => {
    return (liveSettings ?? provider?.settingsConfig ?? {}) as Record<
      string,
      unknown
    >;
  }, [liveSettings, provider?.settingsConfig]);

  const initialData = useMemo(() => {
    if (!provider) return null;
    return {
      name: provider.name,
      notes: provider.notes,
      websiteUrl: provider.websiteUrl,
      settingsConfig: initialSettingsConfig,
      category: provider.category,
      meta: provider.meta,
      icon: provider.icon,
      iconColor: provider.iconColor,
    };
  }, [initialSettingsConfig, open, provider]);

  const handleSubmit = useCallback(
    async (values: ProviderFormValues) => {
      if (!provider) return;

      const parsedConfig = JSON.parse(values.settingsConfig) as Record<
        string,
        unknown
      >;

      const updatedProvider: Provider = {
        ...provider,
        name: values.name.trim(),
        notes: values.notes?.trim() || undefined,
        websiteUrl: values.websiteUrl?.trim() || undefined,
        settingsConfig: parsedConfig,
        icon: values.icon?.trim() || undefined,
        iconColor: values.iconColor?.trim() || undefined,
        ...(values.presetCategory ? { category: values.presetCategory } : {}),
        ...(values.meta ? { meta: values.meta } : {}),
      };

      await onSubmit(updatedProvider);
      onOpenChange(false);
    },
    [onOpenChange, onSubmit, provider],
  );

  if (!provider || !initialData) {
    return null;
  }

  return (
    <FullScreenPanel
      isOpen={open}
      title={t("provider.editProvider")}
      onClose={() => onOpenChange(false)}
      footer={
        <Button
          type="submit"
          form="provider-form"
          disabled={isFormSubmitting}
          className="bg-primary text-primary-foreground hover:bg-primary/90"
        >
          <Save className="h-4 w-4 mr-2" />
          {t("common.save")}
        </Button>
      }
    >
      <ProviderForm
        appId={appId}
        providerId={provider.id}
        submitLabel={t("common.save")}
        onSubmit={handleSubmit}
        onCancel={() => onOpenChange(false)}
        onSubmittingChange={setIsFormSubmitting}
        initialData={initialData}
        showButtons={false}
      />
    </FullScreenPanel>
  );
}
