import React, { useEffect, useState } from "react";
import { useAuth } from "../AuthContext";
import { listAgents, createAgent, getBillingAgents } from "../api";
import type {
  AgentSummary,
  BillingResponse,
  CreatedAgentResponse,
} from "../api";

export const AgentsPage: React.FC = () => {
  const { token, email } = useAuth();

  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [billingRaw, setBillingRaw] = useState<BillingResponse | null>(null);
  const [walletsByAgent, setWalletsByAgent] = useState<Record<string, number>>({});
  const [lastCreatedAgent, setLastCreatedAgent] =
    useState<CreatedAgentResponse | null>(null);

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

      const map: Record<string, number> = {};
      (result.wallets || []).forEach((w) => {
        if (w.agentId) {
          map[w.agentId] = w.credits ?? 0;
        }
      });

      setWalletsByAgent(map);
      setBillingRaw(result);
      setStatus("Billing loaded.");
    } catch (err: any) {
      setStatus(err.message || String(err));
    }
  };

  const handleCreate = async () => {
    if (!token) return;
    setStatus("Creating agent...");
    try {
      const created = await createAgent(token);
      setLastCreatedAgent(created); // 🌟 store the one-time secret response
      setStatus(`Agent created: ${created.agentId}. Reloading list...`);
      await loadAgents();
      await loadBilling();
    } catch (err: any) {
      setStatus(err.message || String(err));
    }
  };

  useEffect(() => {
    if (token) {
      loadAgents();
      loadBilling();
    }
  }, [token]);

  if (!token) {
    return (
      <div>
        <h2>Agents</h2>
        <p>Please log in first on the Auth tab.</p>
      </div>
    );
  }

  const totalCredits = agents.reduce(
    (sum, a) => sum + (walletsByAgent[a.agentId] ?? 0),
    0
  );

  return (
    <div
      style={{
        maxWidth: 900,
        margin: "0 auto",
      }}
    >
      {/* Main card */}
      <div
        style={{
          backgroundColor: "#ffffff",
          borderRadius: 8,
          border: "1px solid #e5e7eb",
          padding: 20,
          boxShadow: "0 1px 2px rgba(0,0,0,0.04)",
        }}
      >
        <h2 style={{ marginTop: 0, marginBottom: 4 }}>My Agents</h2>
        <p style={{ fontSize: 13, color: "#4b5563", marginTop: 0 }}>
          Logged in as <strong>{email}</strong>. Each agent has a cryptographic
          identity and a wallet of credits with this demo site.
        </p>

        {/* 🔐 COPY YOUR PRIVATE KEY PANEL – THIS IS “STEP D” */}
        {lastCreatedAgent && (
          <div
            style={{
              marginTop: 12,
              marginBottom: 16,
              padding: 12,
              borderRadius: 6,
              border: "1px solid #f97316",
              backgroundColor: "#fffbeb",
              fontSize: 13,
            }}
          >
            <div
              style={{
                fontWeight: 600,
                marginBottom: 4,
                color: "#9a3412",
              }}
            >
              New agent created – copy these values now
            </div>
            <p
              style={{
                margin: "4px 0 8px",
                color: "#78350f",
              }}
            >
              This private key is <strong>only shown once</strong>. Store it
              somewhere safe. You will need it to configure your AI agent client
              (e.g. Python).
            </p>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr",
                gap: 8,
                marginBottom: 8,
              }}
            >
              <div>
                <div style={{ fontSize: 12, color: "#6b7280" }}>Agent ID</div>
                <pre
                  style={{
                    margin: 0,
                    padding: 6,
                    backgroundColor: "#f3f4f6",
                    borderRadius: 4,
                    border: "1px solid #e5e7eb",
                    fontSize: 12,
                    overflowX: "auto",
                  }}
                >
{lastCreatedAgent.agentId}
                </pre>
              </div>
              <div>
                <div style={{ fontSize: 12, color: "#6b7280" }}>
                  Private key (base64url)
                </div>
                <pre
                  style={{
                    margin: 0,
                    padding: 6,
                    backgroundColor: "#f3f4f6",
                    borderRadius: 4,
                    border: "1px solid #e5e7eb",
                    fontSize: 12,
                    overflowX: "auto",
                  }}
                >
{lastCreatedAgent.privateKeyBase64}
                </pre>
              </div>
            </div>

            <div
              style={{
                fontSize: 12,
                color: "#6b7280",
                marginBottom: 4,
              }}
            >
              Example Python config snippet:
            </div>
            <pre
              style={{
                margin: 0,
                padding: 6,
                backgroundColor: "#f3f4f6",
                borderRadius: 4,
                border: "1px solid #e5e7eb",
                fontSize: 12,
                overflowX: "auto",
              }}
            >
{`AGENTS = {
  "travel-search": {
    "agent_id": "${lastCreatedAgent.agentId}",
    "private_key": "${lastCreatedAgent.privateKeyBase64}"
  }
}`}
            </pre>

            <div style={{ marginTop: 8 }}>
              <button
                type="button"
                onClick={() => setLastCreatedAgent(null)}
                style={{
                  padding: "4px 8px",
                  fontSize: 12,
                  borderRadius: 4,
                  border: "1px solid #d1d5db",
                  backgroundColor: "#ffffff",
                  cursor: "pointer",
                }}
              >
                I’ve copied this safely – hide
              </button>
            </div>
          </div>
        )}

        {/* Pricing / explanation */}
        <div
          style={{
            marginTop: 12,
            marginBottom: 16,
            padding: 12,
            borderRadius: 6,
            backgroundColor: "#f3f4f6",
            border: "1px solid #e5e7eb",
            fontSize: 13,
          }}
        >

<div
  style={{
    marginTop: 12,
    marginBottom: 16,
    padding: 12,
    borderRadius: 6,
    backgroundColor: "#f3f4f6",
    border: "1px solid #e5e7eb",
    fontSize: 13,
  }}
>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>
              Payments & pricing (demo – Travel Flights API)
            </div>
            <ul style={{ margin: 0, paddingLeft: 16 }}>
              <li>
                <strong>Provider:</strong> Stripe (test mode).
              </li>
              <li>
                <strong>Who you pay:</strong>{" "}
                <code>travel.sanatdhir.com</code> (Travel Flights API).
              </li>
              <li>
                <strong>Pricing:</strong> 1 credit per flight search, 100 credits = $1.00.
              </li>
              <li>
                When your agent runs out of credits, the HAP gateway automatically creates a
                Stripe payment for this site. On success, your agent’s wallet is refilled.
              </li>
            </ul>
            <p style={{ marginTop: 8, fontSize: 12, color: "#6b7280" }}>
              In the full product, each website owner will configure their own payment
              provider and pricing. As an Agent Developer, you’ll be able to see and control
              your autopay settings per site (coming soon).
            </p>
          </div>

          <ul style={{ margin: 0, paddingLeft: 16 }}>
            <li>1 credit per flight search.</li>
            <li>100 credits = $1.00 (Stripe test mode).</li>
            <li>
              In this demo, credits shown here are for{" "}
              <code>travel.sanatdhir.com</code>.
            </li>
            <li>
              In the full product, each agent will have separate wallets per
              website (e.g. one balance for travel APIs, another for shopping
              APIs), all managed through AgentPassportHQ.
            </li>
          </ul>
        </div>

        {/* Actions */}
        <div style={{ marginBottom: 8, marginTop: 8 }}>
          <button
            onClick={handleCreate}
            style={{
              padding: "6px 12px",
              borderRadius: 6,
              border: "1px solid #d1d5db",
              backgroundColor: "#2563eb",
              color: "#ffffff",
              cursor: "pointer",
            }}
          >
            Create new agent
          </button>
          <button
            onClick={loadAgents}
            style={{
              padding: "6px 12px",
              borderRadius: 6,
              border: "1px solid #d1d5db",
              backgroundColor: "#ffffff",
              color: "#111827",
              cursor: "pointer",
              marginLeft: 8,
            }}
          >
            Refresh agents
          </button>
          <button
            onClick={loadBilling}
            style={{
              padding: "6px 12px",
              borderRadius: 6,
              border: "1px solid #d1d5db",
              backgroundColor: "#ffffff",
              color: "#111827",
              cursor: "pointer",
              marginLeft: 8,
            }}
          >
            Refresh billing
          </button>
        </div>

        {status && (
          <div style={{ marginTop: 4, fontSize: 12, color: "#6b7280" }}>
            <strong>Status:</strong> {status}
          </div>
        )}

        <div
          style={{
            marginTop: 12,
            fontSize: 12,
            color: "#6b7280",
          }}
        >
          Total credits across your agents (for this demo site):{" "}
          <strong>{totalCredits}</strong>
        </div>

        {/* Agents table */}
        <h3 style={{ marginTop: 20, marginBottom: 8 }}>Agents</h3>

        {agents.length === 0 ? (
          <div style={{ fontSize: 13 }}>
            No agents yet. Click “Create new agent” to generate one.
          </div>
        ) : (
          <table
            style={{
              marginTop: 4,
              width: "100%",
              fontSize: 13,
              borderCollapse: "collapse",
              border: "1px solid #e5e7eb",
            }}
          >
            <thead>
              <tr style={{ backgroundColor: "#f9fafb" }}>
                <th
                  style={{
                    textAlign: "left",
                    padding: 8,
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Agent ID
                </th>
                <th
                  style={{
                    textAlign: "right",
                    padding: 8,
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Credits (Travel Flights API)
                </th>
                <th
                  style={{
                    textAlign: "left",
                    padding: 8,
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Created
                </th>
                <th
                  style={{
                    textAlign: "left",
                    padding: 8,
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.agentId}>
                  <td
                    style={{
                      borderBottom: "1px solid #e5e7eb",
                      padding: 8,
                      fontFamily: "monospace",
                      fontSize: 12,
                    }}
                  >
                    {a.agentId}
                  </td>
                  <td
                    style={{
                      borderBottom: "1px solid #e5e7eb",
                      padding: 8,
                      textAlign: "right",
                    }}
                  >
                    {walletsByAgent[a.agentId] ?? 0}
                  </td>
                  <td
                    style={{
                      borderBottom: "1px solid #e5e7eb",
                      padding: 8,
                    }}
                  >
                    {a.createdAt || "-"}
                  </td>
                  <td
                    style={{
                      borderBottom: "1px solid #e5e7eb",
                      padding: 8,
                    }}
                  >
                    {a.status || "active"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Raw billing for debugging */}
        <h3 style={{ marginTop: 24 }}>Billing (raw JSON)</h3>
        <p style={{ fontSize: 12, color: "#6b7280" }}>
          For debugging / deep dives. In a production UI this would become a
          proper table.
        </p>
        <pre
          style={{
            fontSize: 11,
            backgroundColor: "#f9fafb",
            borderRadius: 4,
            border: "1px solid #e5e7eb",
            padding: 8,
            maxHeight: 260,
            overflow: "auto",
          }}
        >
          {billingRaw ? JSON.stringify(billingRaw, null, 2) : "(no billing loaded yet)"}
        </pre>
      </div>
    </div>
  );
};
