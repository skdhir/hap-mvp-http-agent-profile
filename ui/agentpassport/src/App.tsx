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
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <nav
        style={{
          width: 220,
          borderRight: "1px solid #1f2937",
          padding: 16,
          boxSizing: "border-box",
        }}
      >
        <h2 style={{ fontSize: 16, marginBottom: 8 }}>AgentPassportHQ</h2>
        <button onClick={() => setTab("auth")}>Auth</button>
        <br />
        <button onClick={() => setTab("agents")} style={{ marginTop: 8 }}>
          Agents
        </button>
      </nav>
      <main style={{ flex: 1 }}>
        {tab === "auth" ? <AuthPage /> : <AgentsPage />}
      </main>
    </div>
  );
};
