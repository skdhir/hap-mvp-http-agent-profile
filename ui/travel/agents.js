async function createAgent() {
  const statusEl = document.getElementById("status");
  const outputEl = document.getElementById("output");

  statusEl.textContent = "Creating agent...";
  outputEl.value = "";

  try {
    const res = await fetch("https://api.sanatdhir.com/api/agents", {
      method: "POST",
      // Note: no body and no Content-Type header -> keeps CORS simple
    });

    if (!res.ok) {
      const text = await res.text();
      statusEl.textContent = `Error: ${res.status} ${res.statusText}`;
      outputEl.value = text;
      return;
    }

    const data = await res.json();

    statusEl.textContent =
      "Agent created. Copy these values into your agent client (Colab) and keep the private key safe.";

    // Pretty-print the JSON so it's easy to copy
    outputEl.value = JSON.stringify(data, null, 2);
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Request failed (check browser console for details).";
    outputEl.value = "";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("create-agent-btn");
  btn.addEventListener("click", createAgent);
});
