import { mocha } from "../theme";

export type ConnectionStatus = "disconnected" | "connecting" | "connected";

const statusColors: Record<ConnectionStatus, string> = {
  disconnected: mocha.red,
  connecting: mocha.yellow,
  connected: mocha.green,
};

interface Props {
  status: ConnectionStatus;
  message: string;
}

export function StatusBar({ status, message }: Props) {
  return (
    <div
      style={{
        padding: "0.5rem",
        borderRadius: 6,
        fontSize: "0.8rem",
        marginBottom: "1rem",
        background: mocha.surface0,
        color: statusColors[status],
      }}
    >
      {message}
    </div>
  );
}
