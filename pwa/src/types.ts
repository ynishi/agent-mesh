/** Agent card returned from the CP /agents endpoint. */
export interface AgentCard {
  agent_id: string;
  name: string;
  description?: string;
  capabilities?: { name: string }[];
}

/** A single log entry. */
export interface LogEntry {
  time: string;
  message: string;
  level: "info" | "error" | "send" | "recv";
}

/** Device flow response from /oauth/device. */
export interface DeviceFlowData {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}
