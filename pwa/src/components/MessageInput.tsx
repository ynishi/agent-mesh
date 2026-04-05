import { useState } from "react";
import { mocha } from "../theme";

interface Props {
  onSend: (text: string) => void;
  disabled: boolean;
  sending: boolean;
}

export function MessageInput({ onSend, disabled, sending }: Props) {
  const [text, setText] = useState("");

  function handleSubmit() {
    const trimmed = text.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setText("");
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  }

  return (
    <div
      style={{
        display: "flex",
        gap: "0.5rem",
        padding: "0.5rem",
        background: mocha.mantle,
        borderRadius: 6,
      }}
    >
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={disabled ? "Select an agent first" : "Type a message..."}
        disabled={disabled || sending}
        rows={1}
        style={{
          flex: 1,
          padding: "0.5rem",
          background: mocha.surface0,
          border: `1px solid ${mocha.surface1}`,
          color: mocha.text,
          borderRadius: 6,
          fontSize: "0.85rem",
          resize: "none",
          fontFamily: "inherit",
          minHeight: "2.2rem",
          maxHeight: "6rem",
          overflow: "auto",
        }}
      />
      <button
        onClick={handleSubmit}
        disabled={disabled || sending || !text.trim()}
        style={{
          padding: "0.5rem 1rem",
          background: disabled || sending || !text.trim() ? mocha.surface1 : mocha.mauve,
          color: disabled || sending || !text.trim() ? mocha.overlay0 : mocha.crust,
          border: "none",
          borderRadius: 6,
          cursor: disabled || sending ? "not-allowed" : "pointer",
          fontSize: "0.85rem",
          fontWeight: 600,
          whiteSpace: "nowrap",
          alignSelf: "flex-end",
        }}
      >
        {sending ? "..." : "Send"}
      </button>
    </div>
  );
}
