// ui/agentpassport/src/App.tsx
import React from "react";
import { AuthPage } from "./pages/AuthPage";
import { AgentsPage } from "./pages/AgentsPage";
import { useAuth } from "./AuthContext";

export const App: React.FC = () => {
  const { token } = useAuth();
  const [tab, setTab] = React.useState<"auth" | "agents">("auth");

  React.useEffect(() => {
    if (token) setTab("agents");
  }, [token]);

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#f9fafb", // light gray background
        color: "#111827",           // dark text
        fontFamily:
          "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      }}
    >
      {/* Top header */}
      <header
        style={{
          borderBottom: "1px solid #e5e7eb",
          padding: "12px 24px",
          display: "flex",
          alignItems: "baseline",
          justifyContent: "space-between",
          backgroundColor: "#ffffff",
        }}
      >
        <div>
          <div style={{ fontSize: 20, fontWeight: 600 }}>AgentPassportHQ</div>
          <div style={{ fontSize: 13, color: "#6b7280", marginTop: 2 }}>
            Agent developer portal – register agents, get keys, and see credits
            for your AI agents.
          </div>
        </div>
        <div style={{ fontSize: 12, color: "#6b7280" }}>
          Demo: Travel Flights API protected by HAP
        </div>
      </header>

      {/* Main layout */}
      <div style={{ display: "flex", minHeight: "calc(100vh - 56px)" }}>
        {/* Sidebar */}
        <nav
          style={{
            width: 220,
            borderRight: "1px solid #e5e7eb",
            backgroundColor: "#f3f4f6",
            padding: 16,
            boxSizing: "border-box",
            fontSize: 14,
          }}
        >
          <div style={{ marginBottom: 8, fontWeight: 500 }}>Navigation</div>
          <button
            onClick={() => setTab("auth")}
            style={{
              display: "block",
              width: "100%",
              marginBottom: 6,
              padding: "8px 10px",
              textAlign: "left",
              borderRadius: 6,
              border: "1px solid #d1d5db",
              backgroundColor: tab === "auth" ? "#e5e7eb" : "#ffffff",
              color: "#111827",
              cursor: "pointer",
            }}
          >
            Auth (sign up / login)
          </button>
          <button
            onClick={() => setTab("agents")}
            style={{
              display: "block",
              width: "100%",
              padding: "8px 10px",
              textAlign: "left",
              borderRadius: 6,
              border: "1px solid #d1d5db",
              backgroundColor: tab === "agents" ? "#e5e7eb" : "#ffffff",
              color: "#111827",
              cursor: "pointer",
              marginTop: 4,
            }}
          >
            Agents & credits
          </button>
        </nav>

        {/* Content */}
        <main
          style={{
            flex: 1,
            padding: 24,
          }}
        >
          {tab === "auth" ? <AuthPage /> : <AgentsPage />}
        </main>
      </div>
    </div>
  );
};
