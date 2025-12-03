// src/api.ts
import { API_BASE } from "./config";

export type AgentSummary = {
  agentId: string;
  keyId?: string;
  ownerEmail?: string;
  ownerUserId?: string;
  status?: string;
  createdAt?: string;
};

export type Wallet = {
  agentId: string;
  credits?: number;
  updatedAt?: string;
};

export type BillingResponse = {
  status?: string;
  wallets?: Wallet[];
  paymentSessions?: any;
};

export async function listAgents(token: string): Promise<AgentSummary[]> {
  const resp = await fetch(`${API_BASE}/api/agents`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.message || `Failed to list agents (${resp.status})`);
  }

  return data.agents || [];
}

export async function createAgent(token: string): Promise<any> {
  const resp = await fetch(`${API_BASE}/api/agents`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: "", // no body needed for now
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.message || `Failed to create agent (${resp.status})`);
  }

  return data;
}

export async function getBillingAgents(token: string): Promise<BillingResponse> {
  const resp = await fetch(`${API_BASE}/api/billing/agents`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.message || `Failed to get billing (${resp.status})`);
  }

  return data;
}
