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
  const [targetId, setTargetId] = useState("");
  const [capability, setCapability] = useState("chat");

  const targetAgent = agents.find((a) => a.agent_id === targetId);
  const targetCaps = targetAgent?.capabilities?.map((c) => c.name) ?? [];

  const send = useCallback(
    async (input: string) => {
      if (!client || !targetId.trim() || !input.trim()) return;

      const payloadStr = buildPayload(capability, input);
      const msgId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

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
