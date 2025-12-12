import { useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { Server, Key, Lock, Eye, EyeOff, FolderOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FullScreenPanel } from "@/components/common/FullScreenPanel";
import type { ManagedServer, SSHAuthType } from "@/types/server";

interface AddServerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (server: Omit<ManagedServer, "id" | "createdAt">) => void;
  editingServer?: ManagedServer | null;
}

export function AddServerDialog({
  open,
  onOpenChange,
  onSubmit,
  editingServer,
}: AddServerDialogProps) {
  const { t } = useTranslation();
  const isEditing = Boolean(editingServer);

  // 表单状态
  const [name, setName] = useState(editingServer?.name || "");
  const [host, setHost] = useState(editingServer?.sshConfig?.host || "");
  const [port, setPort] = useState(
    editingServer?.sshConfig?.port?.toString() || "22"
  );
  const [username, setUsername] = useState(
    editingServer?.sshConfig?.username || ""
  );
  const [authType, setAuthType] = useState<SSHAuthType>(
    editingServer?.sshConfig?.authType || "password"
  );
  const [password, setPassword] = useState(
    editingServer?.sshConfig?.password || ""
  );
  const [privateKeyPath, setPrivateKeyPath] = useState(
    editingServer?.sshConfig?.privateKeyPath || ""
  );
  const [passphrase, setPassphrase] = useState(
    editingServer?.sshConfig?.passphrase || ""
  );
  const [showPassword, setShowPassword] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);

  // 表单验证
  const isValid =
    name.trim() !== "" &&
    host.trim() !== "" &&
    username.trim() !== "" &&
    (authType === "password"
      ? password.trim() !== ""
      : privateKeyPath.trim() !== "");

  // 重置表单
  const resetForm = useCallback(() => {
    setName("");
    setHost("");
    setPort("22");
    setUsername("");
    setAuthType("password");
    setPassword("");
    setPrivateKeyPath("");
    setPassphrase("");
    setShowPassword(false);
    setShowPassphrase(false);
  }, []);

  // 提交表单
  const handleSubmit = useCallback(() => {
    if (!isValid) return;

    const serverData: Omit<ManagedServer, "id" | "createdAt"> = {
      name: name.trim(),
      connectionType: "ssh",
      status: "disconnected",
      sshConfig: {
        host: host.trim(),
        port: parseInt(port) || 22,
        username: username.trim(),
        authType,
        ...(authType === "password"
          ? { password: password.trim() }
          : {
              privateKeyPath: privateKeyPath.trim(),
              passphrase: passphrase.trim() || undefined,
            }),
      },
    };

    onSubmit(serverData);
    resetForm();
    onOpenChange(false);
  }, [
    isValid,
    name,
    host,
    port,
    username,
    authType,
    password,
    privateKeyPath,
    passphrase,
    onSubmit,
    resetForm,
    onOpenChange,
  ]);

  // 关闭对话框
  const handleClose = useCallback(() => {
    resetForm();
    onOpenChange(false);
  }, [resetForm, onOpenChange]);

  return (
    <FullScreenPanel
      isOpen={open}
      title={
        isEditing
          ? t("server.editTitle", { defaultValue: "编辑服务器" })
          : t("server.addTitle", { defaultValue: "添加服务器" })
      }
      onClose={handleClose}
      footer={
        <>
          <Button variant="outline" onClick={handleClose}>
            {t("common.cancel", { defaultValue: "取消" })}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={!isValid}
            className="bg-orange-500 hover:bg-orange-600"
          >
            {isEditing
              ? t("common.save", { defaultValue: "保存" })
              : t("server.add", { defaultValue: "添加服务器" })}
          </Button>
        </>
      }
    >
      <div className="space-y-6">
        {/* 服务器名称 */}
        <div className="space-y-2">
          <Label htmlFor="server-name">
            {t("server.form.name", { defaultValue: "服务器名称" })}
          </Label>
          <div className="relative">
            <Server className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              id="server-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t("server.form.namePlaceholder", {
                defaultValue: "例如：生产服务器",
              })}
              className="pl-10"
            />
          </div>
        </div>

        {/* SSH 连接信息 */}
        <div className="space-y-4">
          <h3 className="text-sm font-medium text-foreground">
            {t("server.form.sshConfig", { defaultValue: "SSH 连接配置" })}
          </h3>

          {/* 主机地址和端口 */}
          <div className="grid grid-cols-3 gap-4">
            <div className="col-span-2 space-y-2">
              <Label htmlFor="ssh-host">
                {t("server.form.host", { defaultValue: "主机地址" })}
              </Label>
              <Input
                id="ssh-host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="192.168.1.100 或 example.com"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ssh-port">
                {t("server.form.port", { defaultValue: "端口" })}
              </Label>
              <Input
                id="ssh-port"
                type="number"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="22"
              />
            </div>
          </div>

          {/* 用户名 */}
          <div className="space-y-2">
            <Label htmlFor="ssh-username">
              {t("server.form.username", { defaultValue: "用户名" })}
            </Label>
            <Input
              id="ssh-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="root"
            />
          </div>

          {/* 认证方式选择 */}
          <div className="space-y-2">
            <Label>
              {t("server.form.authType", { defaultValue: "认证方式" })}
            </Label>
            <div className="flex gap-2">
              <Button
                type="button"
                variant={authType === "password" ? "default" : "outline"}
                onClick={() => setAuthType("password")}
                className="flex-1"
              >
                <Lock className="h-4 w-4 mr-2" />
                {t("server.form.passwordAuth", { defaultValue: "密码认证" })}
              </Button>
              <Button
                type="button"
                variant={authType === "key" ? "default" : "outline"}
                onClick={() => setAuthType("key")}
                className="flex-1"
              >
                <Key className="h-4 w-4 mr-2" />
                {t("server.form.keyAuth", { defaultValue: "密钥认证" })}
              </Button>
            </div>
          </div>

          {/* 密码输入 */}
          {authType === "password" && (
            <div className="space-y-2">
              <Label htmlFor="ssh-password">
                {t("server.form.password", { defaultValue: "密码" })}
              </Label>
              <div className="relative">
                <Input
                  id="ssh-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>
          )}

          {/* 私钥路径和密码短语 */}
          {authType === "key" && (
            <>
              <div className="space-y-2">
                <Label htmlFor="ssh-key-path">
                  {t("server.form.privateKeyPath", {
                    defaultValue: "私钥文件路径",
                  })}
                </Label>
                <div className="relative">
                  <FolderOpen className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="ssh-key-path"
                    value={privateKeyPath}
                    onChange={(e) => setPrivateKeyPath(e.target.value)}
                    placeholder="~/.ssh/id_rsa"
                    className="pl-10"
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="ssh-passphrase">
                  {t("server.form.passphrase", {
                    defaultValue: "密钥密码（可选）",
                  })}
                </Label>
                <div className="relative">
                  <Input
                    id="ssh-passphrase"
                    type={showPassphrase ? "text" : "password"}
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    placeholder={t("server.form.passphrasePlaceholder", {
                      defaultValue: "如果密钥有密码请输入",
                    })}
                    className="pr-10"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                    onClick={() => setShowPassphrase(!showPassphrase)}
                  >
                    {showPassphrase ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
            </>
          )}
        </div>

        {/* 提示信息 */}
        <div className="rounded-lg bg-muted/50 p-4 text-sm text-muted-foreground">
          <p>
            {t("server.form.hint", {
              defaultValue:
                "添加远程服务器后，您可以管理该服务器上的配置文件。请确保 SSH 连接信息正确。",
            })}
          </p>
        </div>
      </div>
    </FullScreenPanel>
  );
}
