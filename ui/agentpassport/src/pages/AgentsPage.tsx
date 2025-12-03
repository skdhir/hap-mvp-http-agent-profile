// src/pages/AgentsPage.tsx
import React, { useEffect, useState } from "react";
import { useAuth } from "../AuthContext";
import type { AgentSummary} from "../api";
import { listAgents, createAgent, getBillingAgents } from "../api";

export const AgentsPage: React.FC = () => {
  const { token, email } = useAuth();

  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  //const [setBillingRaw] = useState<BillingResponse | null>(null);
  const [walletsByAgent, setWalletsByAgent] = useState<Record<string, number>>({});

  const loadAgents = async () => {
    if (!token) return;
    setStatus("Loading agents...");
    try {
      const result = await listAgents(token);
      setAgents(result);
      setStatus(`Loaded ${result.length} agents.`);
    } catch (err: any) {
      setStatus(err.message || String(err));
    }
  };

  const loadBilling = async () => {
    if (!token) return;
    setStatus("Loading billing...");
    try {
      const result = await getBillingAgents(token);

      // Build a quick lookup: agentId -> credits
      const map: Record<string, number> = {};
      (result.wallets || []).forEach((w) => {
        if (w.agentId) {
          map[w.agentId] = w.credits ?? 0;
        }
      });

      setWalletsByAgent(map);
      setStatus("Billing loaded.");
    } catch (err: any) {
      setStatus(err.message || String(err));
    }
  };

  const handleCreate = async () => {
    if (!token) return;
    setStatus("Creating agent...");
    try {
      await createAgent(token);
      setStatus("Agent created. Reloading list...");
      await loadAgents();
      await loadBilling();
    } catch (err: any) {
      setStatus(err.message || String(err));
    }
  };

  useEffect(() => {
    if (token) {
      // initial load when logged in
      loadAgents();
      loadBilling();
    }
  }, [token]);

  if (!token) {
    return (
      <div style={{ padding: 24 }}>
        <h2>Agents</h2>
        <p>Please log in first on the Auth tab.</p>
      </div>
    );
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>My Agents</h2>
      <p style={{ fontSize: 13, color: "#6b7280" }}>
        Logged in as <strong>{email}</strong>
      </p>

      <div style={{ marginBottom: 8 }}>
        <button onClick={handleCreate}>Create new agent</button>
        <button onClick={loadAgents} style={{ marginLeft: 8 }}>
          Refresh
        </button>
        <button onClick={loadBilling} style={{ marginLeft: 8 }}>
          Refresh billing
        </button>
      </div>

      {status && (
        <div style={{ marginTop: 4, fontSize: 12 }}>
          <strong>Status:</strong> {status}
        </div>
      )}

      <h3 style={{ marginTop: 16 }}>Agents</h3>

      {agents.length === 0 ? (
        <div style={{ fontSize: 13 }}>No agents yet.</div>
      ) : (
        <table
          style={{
            marginTop: 8,
            fontSize: 12,
            borderCollapse: "collapse",
            minWidth: "60%",
          }}
        >
          <thead>
            <tr>
              <th style={{ borderBottom: "1px solid #374151", padding: 4, textAlign: "left" }}>
                Agent ID
              </th>
              <th style={{ borderBottom: "1px solid #374151", padding: 4, textAlign: "left" }}>
                Credits
              </th>
              <th style={{ borderBottom: "1px solid #374151", padding: 4, textAlign: "left" }}>
                Created
              </th>
              <th style={{ borderBottom: "1px solid #374151", padding: 4, textAlign: "left" }}>
                Status
              </th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.agentId}>
                <td style={{ borderBottom: "1px solid #1f2933", padding: 4 }}>
                  <code>{a.agentId}</code>
                </td>
                <td style={{ borderBottom: "1px solid #1f2933", padding: 4 }}>
                  {walletsByAgent[a.agentId] ?? 0}
                </td>
                <td style={{ borderBottom: "1px solid #1f2933", padding: 4 }}>
                  {a.createdAt || "-"}
                </td>
                <td style={{ borderBottom: "1px solid #1f2933", padding: 4 }}>
                  {a.status || "active"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

    </div>
  );
};
