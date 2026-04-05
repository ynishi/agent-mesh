import { useCallback, useState } from "react";
import type { MeshClient } from "../wasm";
import type { AgentCard, ChatMessage } from "../types";

/** Build the request payload from user input and selected capability. */
function buildPayload(capability: string, input: string): string {
  // Try parsing as JSON first
  try {
    const parsed = JSON.parse(input);
    if (typeof parsed === "object" && parsed !== null) {
      return JSON.stringify({ capability, ...parsed });
    }
  } catch {
    // not JSON, use as message
  }
  return JSON.stringify({ capability, message: input });
}

export function useChat(
  client: MeshClient | null,
  agents: AgentCard[],
  log: (msg: string, level?: "info" | "error" | "send" | "recv") => void,
) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [sending, setSending] = useState(false);
  const [targetId, setTargetIdRaw] = useState("");
  const [capability, setCapability] = useState("chat");

  const targetAgent = agents.find((a) => a.agent_id === targetId);
  const targetCaps = targetAgent?.capabilities?.map((c) => c.name) ?? [];

  const setTargetId = useCallback(
    (id: string) => {
      setTargetIdRaw(id);
      const agent = agents.find((a) => a.agent_id === id);
      const caps = agent?.capabilities?.map((c) => c.name) ?? [];
      if (caps.length > 0 && !caps.includes(capability) && caps[0]) {
        setCapability(caps[0]);
      }
    },
    [agents, capability],
  );

  const send = useCallback(
    async (input: string) => {
      if (!client || !targetId.trim() || !input.trim()) return;

      const payloadStr = buildPayload(capability, input);
      const msgId = crypto.randomUUID();

      const sent: ChatMessage = {
        id: msgId,
        direction: "sent",
        agentId: targetId,
        agentName: targetAgent?.name,
        capability,
        payload: input,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, sent]);
      setSending(true);

      try {
        log(`-> ${targetId.substring(0, 12)}... [${capability}]`, "send");
        const response = await client.request(targetId, payloadStr);
        log(`<- ${response.substring(0, 100)}`, "recv");

        // Pretty-print if JSON
        let display = response;
        try {
          display = JSON.stringify(JSON.parse(response), null, 2);
        } catch {
          // plain text
        }

        const recv: ChatMessage = {
          id: `${msgId}-reply`,
          direction: "received",
          agentId: targetId,
          agentName: targetAgent?.name,
          capability,
          payload: display,
          timestamp: new Date(),
        };
        setMessages((prev) => [...prev, recv]);
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        log(`Error: ${errMsg}`, "error");

        const errReply: ChatMessage = {
          id: `${msgId}-error`,
          direction: "received",
          agentId: targetId,
          agentName: targetAgent?.name,
          capability,
          payload: `[Error] ${errMsg}`,
          timestamp: new Date(),
        };
        setMessages((prev) => [...prev, errReply]);
      } finally {
        setSending(false);
      }
    },
    [client, targetId, capability, targetAgent, log],
  );

  return {
    messages,
    sending,
    targetId,
    setTargetId,
    capability,
    setCapability,
    targetCaps,
    targetAgent,
    send,
  } as const;
}
