import { invoke } from "@tauri-apps/api/core";
import type { ManagedServersMap } from "@/types/server";

export const serversApi = {
  getManagedServers: async (): Promise<ManagedServersMap> => {
    return invoke("get_managed_servers");
  },

  setManagedServers: async (servers: ManagedServersMap): Promise<void> => {
    return invoke("set_managed_servers", { servers });
  },
};

