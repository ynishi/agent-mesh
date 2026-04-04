/**
 * WASM initialization and MeshClient re-export.
 *
 * wasm-pack generates `init()` + `MeshClient` class.
 * We wrap init() to ensure it's only called once.
 *
 * The `?url` suffix tells Vite to emit the .wasm file as an asset
 * and return its hashed URL — required because wasm-bindgen's
 * default `new URL(..., import.meta.url)` doesn't resolve correctly
 * when the source lives behind a Vite alias.
 */
import wasmInit, { MeshClient } from "@wasm/agent_mesh_wasm";
import wasmUrl from "@wasm/agent_mesh_wasm_bg.wasm?url";

let initialized = false;

export async function ensureWasm(): Promise<void> {
  if (!initialized) {
    await wasmInit(wasmUrl);
    initialized = true;
  }
}

export { MeshClient };
