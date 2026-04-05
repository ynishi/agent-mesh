import { mocha } from "../theme";
import type { AgentCard } from "../types";
import type { MeshClient } from "../wasm";
import { useChat } from "../hooks/useChat";
import { AgentSelector } from "./AgentSelector";
import { MessageList } from "./MessageList";
import { MessageInput } from "./MessageInput";

interface Props {
  client: MeshClient;
  agents: AgentCard[];
  myAgentId: string;
  onRefreshAgents: () => void;
  log: (msg: string, level?: "info" | "error" | "send" | "recv") => void;
}

export function ChatView({ client, agents, myAgentId, onRefreshAgents, log }: Props) {
  const {
    messages,
    sending,
    targetId,
    setTargetId,
    capability,
    setCapability,
    targetCaps,
    send,
  } = useChat(client, agents, log);

  return (
    <section
      style={{
        display: "flex",
        flexDirection: "column",
        flex: 1,
        minHeight: 0,
        background: mocha.base,
        borderRadius: 6,
        border: `1px solid ${mocha.surface0}`,
        overflow: "hidden",
      }}
    >
      <AgentSelector
        agents={agents}
        myAgentId={myAgentId}
        targetId={targetId}
        onTargetChange={setTargetId}
        capability={capability}
        onCapabilityChange={setCapability}
        targetCaps={targetCaps}
        onRefresh={onRefreshAgents}
      />

      <MessageList messages={messages} />

      <MessageInput
        onSend={send}
        disabled={!targetId}
        sending={sending}
      />
    </section>
  );
}
