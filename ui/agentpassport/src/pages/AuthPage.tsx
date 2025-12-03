import React, { useState } from "react";
import { useAuth } from "../AuthContext";

export const AuthPage: React.FC = () => {
  const { token, email, login, signup, logout } = useAuth();
  const [formEmail, setFormEmail] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [status, setStatus] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus(mode === "login" ? "Logging in..." : "Signing up...");
    try {
      if (mode === "login") {
        await login(formEmail, formPassword);
        setStatus("Logged in.");
      } else {
        await signup(formEmail, formPassword);
        setStatus("Signed up and logged in.");
      }
    } catch (err: any) {
      setStatus(err.message || String(err));
    }
  };

  return (
    <div style={{ maxWidth: 420, margin: "0 auto", padding: 24 }}>
      <h1>AgentPassportHQ</h1>
      <p style={{ color: "#9ca3af", fontSize: 14 }}>
        Sign up or log in to manage your agents and wallets.
      </p>

      <div style={{ marginBottom: 16 }}>
        {token ? (
          <div style={{ fontSize: 13 }}>
            Logged in as <strong>{email}</strong>{" "}
            <button onClick={logout} style={{ marginLeft: 8 }}>
              Logout
            </button>
          </div>
        ) : (
          <div style={{ fontSize: 13, color: "#f97316" }}>Not logged in.</div>
        )}
      </div>

      <div style={{ marginBottom: 8 }}>
        <button
          type="button"
          onClick={() => setMode("login")}
          disabled={mode === "login"}
        >
          Login
        </button>
        <button
          type="button"
          onClick={() => setMode("signup")}
          disabled={mode === "signup"}
          style={{ marginLeft: 8 }}
        >
          Sign up
        </button>
      </div>

      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 8 }}>
          <label>Email</label>
          <input
            type="email"
            value={formEmail}
            onChange={(e) => setFormEmail(e.target.value)}
            required
            style={{ width: "100%" }}
          />
        </div>
        <div style={{ marginBottom: 8 }}>
          <label>Password</label>
          <input
            type="password"
            value={formPassword}
            onChange={(e) => setFormPassword(e.target.value)}
            required
            style={{ width: "100%" }}
          />
        </div>
        <button type="submit">{mode === "login" ? "Log in" : "Sign up"}</button>
      </form>

      {status && (
        <div style={{ marginTop: 8, fontSize: 12 }}>
          <strong>Status:</strong> {status}
        </div>
      )}
    </div>
  );
};
