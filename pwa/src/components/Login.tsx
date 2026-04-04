import { useState } from "react";
import { mocha } from "../theme";
import type { DeviceFlowData } from "../types";
import { ensureWasm, MeshClient } from "../wasm";
import type { AgentCard } from "../types";

interface Props {
  cp: string;
  relay: string;
  log: (msg: string, level?: "info" | "error" | "send" | "recv") => void;
  onConnected: (client: MeshClient, secretHex: string, token: string) => void;
}

/** Generate 32 random bytes as hex. */
function generateSecretKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function Login({ cp, relay, log, onConnected }: Props) {
  const [loading, setLoading] = useState(false);
  const [showManual, setShowManual] = useState(false);
  const [deviceFlow, setDeviceFlow] = useState<DeviceFlowData | null>(null);
  const [pollStatus, setPollStatus] = useState("Waiting for authorization...");
  const [manualRelay, setManualRelay] = useState("");
  const [manualSecret, setManualSecret] = useState("");

  // -- GitHub Device Flow --
  async function doLogin() {
    setLoading(true);
    try {
      log("Starting GitHub Device Flow...");

      const deviceResp = await fetch(`${cp}/oauth/device`, { method: "POST" });
      if (!deviceResp.ok) {
        const text = await deviceResp.text();
        throw new Error(`Device flow failed: ${deviceResp.status} ${text}`);
      }
      const device: DeviceFlowData = await deviceResp.json();
      setDeviceFlow(device);
      log(`Code: ${device.user_code} — click the link to open GitHub`);

      // Poll for token
      const interval = (device.interval || 5) * 1000;
      const deadline = Date.now() + (device.expires_in || 300) * 1000;

      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, interval));

        const tokenResp = await fetch(`${cp}/oauth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_code: device.device_code }),
        });
        const tokenData = await tokenResp.json();

        if (tokenData.error) {
          if (
            tokenData.error === "authorization_pending" ||
            tokenData.error === "slow_down"
          ) {
            setPollStatus("Waiting for authorization...");
            continue;
          }
          throw new Error(`OAuth error: ${tokenData.error}`);
        }

        if (tokenData.api_token) {
          log("Login successful!");
          setDeviceFlow(null);
          await registerAndConnect(cp, relay, tokenData.api_token as string);
          return;
        }
      }
      throw new Error("Login timed out");
    } catch (e) {
      log(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
    }
  }

  // -- Auto-register + connect after OAuth --
  async function registerAndConnect(
    cpBase: string,
    relayUrl: string,
    apiToken: string,
  ) {
    log("Registering agent...");
    await ensureWasm();

    const secretHex = generateSecretKey();
    const agentId = MeshClient.deriveAgentId(secretHex);
    log(`Generated agent: ${agentId.substring(0, 16)}...`);

    const regResp = await fetch(`${cpBase}/agents`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiToken}`,
      },
      body: JSON.stringify({
        agent_id: agentId,
        name: "pwa-agent",
        capabilities: [{ name: "chat" }],
      }),
    });
    if (!regResp.ok) {
      const text = await regResp.text();
      throw new Error(`Register failed: ${regResp.status} ${text}`);
    }
    const card: AgentCard = await regResp.json();
    log(`Registered: ${card.name}`);

    log(`Connecting to ${relayUrl}...`);
    const client = await MeshClient.connect(secretHex, relayUrl);
    log(`Connected! Agent ID: ${client.agentId()}`);
    onConnected(client, secretHex, apiToken);
  }

  // -- Manual connect --
  async function doManualConnect() {
    if (!manualSecret.trim()) {
      log("Secret key is required.", "error");
      return;
    }
    setLoading(true);
    try {
      await ensureWasm();
      const url = manualRelay.trim() || relay;
      log(`Connecting to ${url}...`);
      const client = await MeshClient.connect(manualSecret.trim(), url);
      log(`Authenticated. Agent ID: ${client.agentId()}`);
      onConnected(client, manualSecret.trim(), "");
    } catch (e) {
      log(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setLoading(false);
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
        Login
      </h2>

      <button
        onClick={doLogin}
        disabled={loading}
        style={{
          padding: "0.5rem 1rem",
          background: mocha.mauve,
          color: mocha.crust,
          border: "none",
          borderRadius: 6,
          cursor: loading ? "not-allowed" : "pointer",
          fontSize: "0.85rem",
          fontWeight: 600,
          marginRight: "0.5rem",
          opacity: loading ? 0.4 : 1,
        }}
      >
        Login with GitHub
      </button>
      <button
        onClick={() => setShowManual((v) => !v)}
        style={{
          padding: "0.5rem 1rem",
          background: mocha.surface1,
          color: mocha.text,
          border: "none",
          borderRadius: 6,
          cursor: "pointer",
          fontSize: "0.85rem",
          fontWeight: 600,
        }}
      >
        Use Secret Key
      </button>

      {/* Device Flow UI */}
      {deviceFlow && (
        <div style={{ marginTop: "0.75rem" }}>
          <p
            style={{
              fontSize: "0.75rem",
              color: mocha.overlay1,
              marginBottom: "0.25rem",
            }}
          >
            Open the link and enter the code:
          </p>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.5rem",
              margin: "0.5rem 0",
            }}
          >
            <div
              style={{
                fontSize: "1.5rem",
                fontWeight: "bold",
                color: mocha.peach,
                textAlign: "center",
                padding: "0.75rem",
                background: mocha.surface0,
                borderRadius: 6,
                letterSpacing: "0.3rem",
                flex: 1,
              }}
            >
              {deviceFlow.user_code}
            </div>
            <button
              onClick={() => {
                navigator.clipboard.writeText(deviceFlow.user_code).then(
                  () => log("Code copied to clipboard"),
                  () => log("Failed to copy", "error"),
                );
              }}
              style={{
                padding: "0.5rem 0.75rem",
                background: mocha.surface1,
                color: mocha.text,
                border: "none",
                borderRadius: 6,
                cursor: "pointer",
                fontSize: "0.85rem",
                fontWeight: 600,
                whiteSpace: "nowrap",
              }}
            >
              Copy
            </button>
          </div>
          <p style={{ textAlign: "center", margin: "0.5rem 0" }}>
            <a
              href={deviceFlow.verification_uri}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: mocha.sapphire }}
            >
              Open GitHub
            </a>
          </p>
          <p
            style={{
              fontSize: "0.75rem",
              color: mocha.overlay1,
            }}
          >
            {pollStatus}
          </p>
        </div>
      )}

      {/* Manual key input */}
      {showManual && (
        <div style={{ marginTop: "0.75rem" }}>
          <Label>Relay URL (blank = same origin)</Label>
          <Input
            value={manualRelay}
            onChange={setManualRelay}
            placeholder="wss://agent-mesh.fly.dev/relay/ws"
          />
          <Label>Secret Key (hex)</Label>
          <Input
            value={manualSecret}
            onChange={setManualSecret}
            placeholder="64 hex chars from ~/.mesh/config.toml"
          />
          <button
            onClick={doManualConnect}
            disabled={loading}
            style={{
              padding: "0.5rem 1rem",
              background: mocha.mauve,
              color: mocha.crust,
              border: "none",
              borderRadius: 6,
              cursor: loading ? "not-allowed" : "pointer",
              fontSize: "0.85rem",
              fontWeight: 600,
              opacity: loading ? 0.4 : 1,
            }}
          >
            Connect
          </button>
        </div>
      )}
    </section>
  );
}

// -- Shared small components --

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label
      style={{
        display: "block",
        fontSize: "0.8rem",
        color: mocha.subtext0,
        marginBottom: "0.25rem",
      }}
    >
      {children}
    </label>
  );
}

function Input({
  value,
  onChange,
  placeholder,
  readOnly,
  type,
  style,
}: {
  value: string;
  onChange?: (v: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  type?: string;
  style?: React.CSSProperties;
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={onChange ? (e) => onChange(e.target.value) : undefined}
      placeholder={placeholder}
      readOnly={readOnly}
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
        ...style,
      }}
    />
  );
}
