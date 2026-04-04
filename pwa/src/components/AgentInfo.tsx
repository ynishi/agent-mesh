import { mocha } from "../theme";

interface Props {
  agentId: string;
  secretHex: string;
  log: (msg: string, level?: "info" | "error" | "send" | "recv") => void;
}

export function AgentInfo({ agentId, secretHex, log }: Props) {
  function copySecret() {
    navigator.clipboard.writeText(secretHex).then(
      () => log("Secret key copied to clipboard"),
      () => log("Failed to copy", "error"),
    );
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
        Agent
      </h2>

      <label
        style={{
          display: "block",
          fontSize: "0.8rem",
          color: mocha.subtext0,
          marginBottom: "0.25rem",
        }}
      >
        Agent ID
      </label>
      <input
        value={agentId}
        readOnly
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
        Secret Key (save this!)
      </label>
      <div style={{ display: "flex", gap: "0.25rem", alignItems: "center" }}>
        <input
          type="password"
          value={secretHex}
          readOnly
          style={{
            flex: 1,
            padding: "0.5rem",
            background: mocha.surface0,
            border: `1px solid ${mocha.surface1}`,
            color: mocha.text,
            borderRadius: 6,
            fontFamily: "monospace",
            fontSize: "0.85rem",
          }}
        />
        <button
          onClick={copySecret}
          style={{
            padding: "0.5rem 1rem",
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
    </section>
  );
}
