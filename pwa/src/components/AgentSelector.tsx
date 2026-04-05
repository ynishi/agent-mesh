import { mocha } from "../theme";
import type { AgentCard } from "../types";

interface Props {
  agents: AgentCard[];
  myAgentId: string;
  targetId: string;
  onTargetChange: (id: string) => void;
  capability: string;
  onCapabilityChange: (cap: string) => void;
  targetCaps: string[];
  onRefresh: () => void;
}

export function AgentSelector({
  agents,
  myAgentId,
  targetId,
  onTargetChange,
  capability,
  onCapabilityChange,
  targetCaps,
  onRefresh,
}: Props) {
  const others = agents.filter((a) => a.agent_id !== myAgentId);

  return (
    <div
      style={{
        display: "flex",
        gap: "0.5rem",
        alignItems: "center",
        flexWrap: "wrap",
        padding: "0.5rem",
        background: mocha.mantle,
        borderRadius: 6,
        marginBottom: "0.5rem",
      }}
    >
      <select
        value={targetId}
        onChange={(e) => onTargetChange(e.target.value)}
        style={{
          flex: 1,
          minWidth: 120,
          padding: "0.4rem",
          background: mocha.surface0,
          border: `1px solid ${mocha.surface1}`,
          color: mocha.text,
          borderRadius: 6,
          fontSize: "0.8rem",
        }}
      >
        <option value="">-- Select Agent --</option>
        {others.map((a) => (
          <option key={a.agent_id} value={a.agent_id}>
            {a.name}
            {a.description ? ` - ${a.description}` : ""}
          </option>
        ))}
      </select>

      {targetCaps.length > 0 && (
        <select
          value={capability}
          onChange={(e) => onCapabilityChange(e.target.value)}
          style={{
            minWidth: 80,
            padding: "0.4rem",
            background: mocha.surface0,
            border: `1px solid ${mocha.surface1}`,
            color: mocha.text,
            borderRadius: 6,
            fontSize: "0.8rem",
          }}
        >
          {targetCaps.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      )}

      <button
        onClick={onRefresh}
        style={{
          padding: "0.4rem 0.6rem",
          background: mocha.surface1,
          color: mocha.text,
          border: "none",
          borderRadius: 6,
          cursor: "pointer",
          fontSize: "0.75rem",
        }}
        title="Refresh agent list"
      >
        Reload
      </button>
    </div>
  );
}
