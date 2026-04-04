import { useEffect, useRef } from "react";
import { mocha } from "../theme";
import type { LogEntry } from "../types";

const levelColors: Record<LogEntry["level"], string> = {
  info: mocha.green,
  error: mocha.red,
  send: mocha.blue,
  recv: mocha.yellow,
};

interface Props {
  entries: LogEntry[];
}

export function Log({ entries }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [entries]);

  return (
    <section>
      <h2 style={{ fontSize: "0.9rem", color: mocha.mauve, marginBottom: "0.5rem" }}>
        Log
      </h2>
      <div
        ref={containerRef}
        style={{
          background: mocha.crust,
          padding: "0.75rem",
          borderRadius: 6,
          fontFamily: "monospace",
          fontSize: "0.75rem",
          maxHeight: 300,
          overflowY: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {entries.map((e, i) => (
          <div key={i} style={{ color: levelColors[e.level] }}>
            [{e.time}] {e.message}
          </div>
        ))}
      </div>
    </section>
  );
}
