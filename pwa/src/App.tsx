import { useCallback, useState } from "react";
import { mocha } from "./theme";
import type { AgentCard } from "./types";
import type { MeshClient } from "./wasm";
import { useLog } from "./hooks/useLog";
import { useApi } from "./hooks/useApi";

import { StatusBar, type ConnectionStatus } from "./components/StatusBar";
import { Login } from "./components/Login";
import { AgentInfo } from "./components/AgentInfo";
import { AgentList } from "./components/AgentList";
import { RequestForm } from "./components/RequestForm";
import { Log } from "./components/Log";

export function App() {
  const [cpUrl, setCpUrl] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [client, setClient] = useState<MeshClient | null>(null);
  const [secretHex, setSecretHex] = useState("");
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [statusMsg, setStatusMsg] = useState("Not logged in");
  const [agents, setAgents] = useState<AgentCard[]>([]);
  const [targetId, setTargetId] = useState("");

  const { entries, log } = useLog();
  const { cp, relay } = useApi(cpUrl);

  const handleConnected = useCallback(
    (c: MeshClient, secret: string, apiToken: string) => {
      setClient(c);
      setSecretHex(secret);
      if (apiToken) setToken(apiToken);
      setStatus("connected");
      const id = c.agentId();
      setStatusMsg(`Connected as ${id.substring(0, 12)}...`);
      // Load agents if we have a token
      if (apiToken) loadAgents(apiToken);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [cp],
  );

  async function loadAgents(overrideToken?: string) {
    const t = overrideToken ?? token;
    if (!t) {
      log("Not logged in (no API token)", "error");
      return;
    }
    try {
      const resp = await fetch(`${cp}/agents`, {
        headers: { Authorization: `Bearer ${t}` },
      });
      if (!resp.ok) {
        const text = await resp.text();
        log(`Failed to list agents: ${resp.status} ${text}`, "error");
        return;
      }
      const list: AgentCard[] = await resp.json();
      setAgents(list);
      log(`Loaded ${list.length} agent(s)`);
    } catch (e) {
      log(
        `Error listing agents: ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  function handleSelectAgent(agentId: string) {
    setTargetId(agentId);
    log(`Selected target: ${agentId.substring(0, 16)}...`);
  }

  return (
    <div
      style={{
        fontFamily:
          "-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif",
        background: mocha.base,
        color: mocha.text,
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <header
        style={{
          background: mocha.mantle,
          padding: "1rem",
          textAlign: "center",
          borderBottom: `1px solid ${mocha.surface0}`,
        }}
      >
        <h1 style={{ fontSize: "1.2rem", color: mocha.mauve, margin: 0 }}>
          agent-mesh
        </h1>
        <p
          style={{
            fontSize: "0.8rem",
            color: mocha.overlay1,
            marginTop: "0.25rem",
          }}
        >
          Private mesh network for AI agents
        </p>
      </header>

      <main
        style={{
          flex: 1,
          padding: "1rem",
          maxWidth: 600,
          margin: "0 auto",
          width: "100%",
        }}
      >
        <StatusBar status={status} message={statusMsg} />

        {!client ? (
          <>
            {/* CP URL input */}
            <section style={{ marginBottom: "1.5rem" }}>
              <label
                style={{
                  display: "block",
                  fontSize: "0.8rem",
                  color: mocha.subtext0,
                  marginBottom: "0.25rem",
                }}
              >
                Server URL (blank = same origin)
              </label>
              <input
                value={cpUrl}
                onChange={(e) => setCpUrl(e.target.value)}
                placeholder="https://agent-mesh.fly.dev"
                style={{
                  width: "100%",
                  padding: "0.5rem",
                  background: mocha.surface0,
                  border: `1px solid ${mocha.surface1}`,
                  color: mocha.text,
                  borderRadius: 6,
                  fontFamily: "monospace",
                  fontSize: "0.85rem",
                  marginBottom: "0.5rem",
                }}
              />
            </section>

            <Login
              cp={cp}
              relay={relay}

              log={log}
              onConnected={handleConnected}
            />
          </>
        ) : (
          <>
            <AgentInfo
              agentId={client.agentId()}
              secretHex={secretHex}
              log={log}
            />
            {token && (
              <AgentList
                agents={agents}
                myAgentId={client.agentId()}
                onSelect={handleSelectAgent}
                onRefresh={() => loadAgents()}
              />
            )}
            <RequestForm
              client={client}
              targetId={targetId}
              onTargetChange={setTargetId}
              log={log}
            />
          </>
        )}

        <Log entries={entries} />
      </main>
    </div>
  );
}
