import { useState } from "react";
import { mocha } from "../theme";

interface Props {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

export function Collapsible({ title, defaultOpen, children }: Props) {
  const [open, setOpen] = useState(defaultOpen ?? false);
  return (
    <section style={{ marginBottom: "0.75rem" }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "0.4rem",
          width: "100%",
          background: "none",
          border: "none",
          color: mocha.subtext0,
          fontSize: "0.8rem",
          cursor: "pointer",
          padding: "0.25rem 0",
          textAlign: "left",
        }}
      >
        <span style={{ fontSize: "0.6rem" }}>{open ? "\u25BC" : "\u25B6"}</span>
        {title}
      </button>
      {open && <div style={{ marginTop: "0.25rem" }}>{children}</div>}
    </section>
  );
}
