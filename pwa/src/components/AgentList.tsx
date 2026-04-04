import { mocha } from "../theme";
import type { AgentCard } from "../types";

interface Props {
  agents: AgentCard[];
  myAgentId: string;
  onSelect: (agentId: string) => void;
  onRefresh: () => void;
}

export function AgentList({ agents, myAgentId, onSelect, onRefresh }: Props) {
  return (
    <section style={{ marginBottom: "1.5rem" }}>
      <h2 style={{ fontSize: "0.9rem", color: mocha.mauve, marginBottom: "0.5rem" }}>
        Agents{" "}
        <button
          onClick={onRefresh}
          style={{
            fontSize: "0.75rem",
            padding: "0.2rem 0.5rem",
            background: mocha.surface1,
            color: mocha.text,
            border: "none",
            borderRadius: 6,
            cursor: "pointer",
          }}
        >
          Refresh
        </button>
      </h2>
      <div style={{ maxHeight: 200, overflowY: "auto" }}>
        {agents.length === 0 ? (
          <p style={{ color: mocha.overlay1, fontSize: "0.8rem" }}>
            No agents found in your group.
          </p>
        ) : (
          agents.map((a) => {
            const isSelf = a.agent_id === myAgentId;
            const caps =
              a.capabilities?.map((c) => c.name).join(", ") || "none";
            return (
              <div
                key={a.agent_id}
                onClick={isSelf ? undefined : () => onSelect(a.agent_id)}
                style={{
                  background: mocha.surface0,
                  border: `1px solid ${mocha.surface1}`,
                  borderRadius: 6,
                  padding: "0.5rem 0.75rem",
                  marginBottom: "0.4rem",
                  cursor: isSelf ? "default" : "pointer",
                  fontSize: "0.8rem",
                  opacity: isSelf ? 0.5 : 1,
                }}
              >
                <span style={{ color: mocha.pink, fontWeight: "bold" }}>
                  {a.name}
                </span>
                {a.description && <span> — {a.description}</span>}
                {isSelf && (
                  <span style={{ color: mocha.overlay1 }}> (you)</span>
                )}
                <div
                  style={{
                    color: mocha.blue,
                    fontFamily: "monospace",
                    fontSize: "0.7rem",
                  }}
                >
                  {a.agent_id}
                </div>
                <div style={{ color: mocha.overlay0, fontSize: "0.7rem" }}>
                  {caps}
                </div>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
