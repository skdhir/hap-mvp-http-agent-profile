import React, { createContext, useContext, useEffect, useState } from "react";
import { API_BASE } from "./config";

type AuthState = {
  token: string | null;
  email: string | null;
};

type AuthContextValue = AuthState & {
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);

  useEffect(() => {
    const storedToken = localStorage.getItem("hapAuthToken");
    const storedEmail = localStorage.getItem("hapAuthEmail");
    setToken(storedToken);
    setEmail(storedEmail);
  }, []);

  const saveAuth = (t: string, e: string) => {
    setToken(t);
    setEmail(e);
    localStorage.setItem("hapAuthToken", t);
    localStorage.setItem("hapAuthEmail", e);
  };

  const login = async (email: string, password: string) => {
    const resp = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.message || "Login failed");
    }
    saveAuth(data.token, data.email);
  };

  const signup = async (email: string, password: string) => {
    const resp = await fetch(`${API_BASE}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.message || "Signup failed");
    }
    saveAuth(data.token, data.email);
  };

  const logout = () => {
    setToken(null);
    setEmail(null);
    localStorage.removeItem("hapAuthToken");
    localStorage.removeItem("hapAuthEmail");
  };

  return (
    <AuthContext.Provider value={{ token, email, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
};
