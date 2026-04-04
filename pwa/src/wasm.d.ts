declare module "@wasm/agent_mesh_wasm" {
  export class MeshClient {
    free(): void;
    agentId(): string;
    static connect(
      secret_key_hex: string,
      relay_url: string,
    ): Promise<MeshClient>;
    static deriveAgentId(secret_key_hex: string): string;
    request(target_agent_id: string, payload_json: string): Promise<string>;
  }

  export class MeshClientWithKey {
    free(): void;
    intoClient(): MeshClient;
    readonly agentId: string;
    readonly secretKeyHex: string;
  }

  export default function init(
    module_or_path?: string | URL | Request,
  ): Promise<unknown>;
}

declare module "@wasm/agent_mesh_wasm_bg.wasm?url" {
  const url: string;
  export default url;
}
