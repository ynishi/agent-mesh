import { useState } from "react";
import { mocha } from "../theme";
import type { MeshClient } from "../wasm";

interface Props {
  client: MeshClient;
  targetId: string;
  onTargetChange: (id: string) => void;
  log: (msg: string, level?: "info" | "error" | "send" | "recv") => void;
}

export function RequestForm({ client, targetId, onTargetChange, log }: Props) {
  const [payload, setPayload] = useState(
    '{"capability": "echo", "message": "hello from PWA"}',
  );
  const [sending, setSending] = useState(false);

  async function doRequest() {
    const target = targetId.trim();
    if (!target) {
      log("Target Agent ID is required", "error");
      return;
    }
    setSending(true);
    try {
      log(`\u2192 Sending to ${target.substring(0, 12)}...`, "send");
      log(`  Payload: ${payload}`, "send");
      const response = await client.request(target, payload);
      log(`\u2190 Response: ${response}`, "recv");
    } catch (e) {
      log(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setSending(false);
    }
  }

  return (
    <section style={{ marginBottom: "1.5rem" }}>
      <h2
        style={{
          fontSize: "0.9rem",
          color: mocha.mauve,
          marginBottom: "0.5rem",
        }}
      >
        Send Request
      </h2>

      <label
        style={{
          display: "block",
          fontSize: "0.8rem",
          color: mocha.subtext0,
          marginBottom: "0.25rem",
        }}
      >
        Target Agent ID
      </label>
      <input
        value={targetId}
        onChange={(e) => onTargetChange(e.target.value)}
        placeholder="base64url-encoded Ed25519 public key"
        style={{
          width: "100%",
          padding: "0.5rem",
          background: mocha.surface0,
          border: `1px solid ${mocha.surface1}`,
          color: mocha.text,
          borderRadius: 6,
          fontFamily: "monospace",
          fontSize: "0.85rem",
          marginBottom: "0.5rem",
        }}
      />

      <label
        style={{
          display: "block",
          fontSize: "0.8rem",
          color: mocha.subtext0,
          marginBottom: "0.25rem",
        }}
      >
        Payload (JSON)
      </label>
      <textarea
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        style={{
          width: "100%",
          padding: "0.5rem",
          background: mocha.surface0,
          border: `1px solid ${mocha.surface1}`,
          color: mocha.text,
          borderRadius: 6,
          fontFamily: "monospace",
          fontSize: "0.85rem",
          marginBottom: "0.5rem",
          minHeight: 80,
          resize: "vertical",
        }}
      />

      <button
        onClick={doRequest}
        disabled={sending}
        style={{
          padding: "0.5rem 1rem",
          background: mocha.mauve,
          color: mocha.crust,
          border: "none",
          borderRadius: 6,
          cursor: sending ? "not-allowed" : "pointer",
          fontSize: "0.85rem",
          fontWeight: 600,
          opacity: sending ? 0.4 : 1,
        }}
      >
        Send Request
      </button>
    </section>
  );
}
