import { useCallback, useRef, useState } from "react";
import type { LogEntry } from "../types";

export function useLog() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const idCounter = useRef(0);

  const log = useCallback(
    (message: string, level: LogEntry["level"] = "info") => {
      const time = new Date().toLocaleTimeString();
      // idCounter ensures stable ordering even with batched state updates
      idCounter.current += 1;
      setEntries((prev) => [...prev, { time, message, level }]);
    },
    [],
  );

  return { entries, log } as const;
}
