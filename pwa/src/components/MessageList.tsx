import { useEffect, useRef } from "react";
import { mocha } from "../theme";
import type { ChatMessage } from "../types";

interface Props {
  messages: ChatMessage[];
}

export function MessageList({ messages }: Props) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  if (messages.length === 0) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: mocha.overlay0,
          fontSize: "0.85rem",
          padding: "2rem",
        }}
      >
        Select an agent and start chatting
      </div>
    );
  }

  return (
    <div
      style={{
        flex: 1,
        overflowY: "auto",
        padding: "0.5rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.5rem",
      }}
    >
      {messages.map((m) => (
        <div
          key={m.id}
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: m.direction === "sent" ? "flex-end" : "flex-start",
          }}
        >
          <div
            style={{
              fontSize: "0.65rem",
              color: mocha.overlay0,
              marginBottom: "0.15rem",
              padding: "0 0.25rem",
            }}
          >
            {m.direction === "sent" ? "You" : m.agentName ?? m.agentId.substring(0, 12)}
            {" "}
            [{m.capability}]
            {" "}
            {m.timestamp.toLocaleTimeString()}
          </div>
          <div
            style={{
              maxWidth: "85%",
              padding: "0.5rem 0.75rem",
              borderRadius: m.direction === "sent" ? "12px 12px 2px 12px" : "12px 12px 12px 2px",
              background: m.direction === "sent" ? mocha.mauve : mocha.surface0,
              color: m.direction === "sent" ? mocha.crust : mocha.text,
              fontSize: "0.8rem",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              fontFamily: m.payload.startsWith("{") || m.payload.startsWith("[")
                ? "monospace"
                : "inherit",
            }}
          >
            {m.payload}
          </div>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}
