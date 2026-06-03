import { decryptFile } from "./crypto.js";

const form = document.getElementById("decrypt-form");
const entryInput = document.getElementById("entry");
const passwordInput = document.getElementById("password");
const statusEl = document.getElementById("status");
const entryField = document.getElementById("entry-field");

let currentObjectUrl = null;

const params = new URLSearchParams(window.location.search);
const entryFromQuery = params.get("entry");
if (entryFromQuery) {
  entryInput.value = entryFromQuery;
  entryField.style.display = "none";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("");

  if (!window.crypto || !window.crypto.subtle) {
    setStatus("WebCrypto is unavailable.", true);
    return;
  }

  const entry = entryFromQuery || entryInput.value.trim();
  const password = passwordInput.value;

  if (!entry) {
    setStatus("エントリーを入力してください。", true);
    return;
  }
  if (!password) {
    setStatus("パスワードを入力してください。", true);
    return;
  }

  try {
    setStatus("複合化中...");
    const encrypted = await loadEncryptedEntry(entry);
    const decrypted = await decryptFile(encrypted, password);
    openDecryptedFile(decrypted);
    setStatus(`${decrypted.meta.name}を開きました。`);
  } catch (error) {
    let message = error.message || "復号に失敗しました。";
    setStatus(message, true);
  }
});

const dataDir = "./data";

async function loadEncryptedEntry(entry) {
  const response = await fetch(`${dataDir}/index.json`);
  if (!response.ok) {
    throw new Error("index.json not found. Serve the project root or copy index.json into src/web.");
  }
  const indexJson = await response.json();
  const fileId = indexJson.indexes?.[entry];
  if (!fileId) {
    throw new Error(`エントリー \"${entry}\" が見つかりません。`);
  }
  const fileResponse = await fetch(`${dataDir}/${fileId}.json`);
  if (!fileResponse.ok) {
    throw new Error(`エントリー \"${entry}\" のファイルが見つかりません。`);
  }
  return await fileResponse.json();
}

function openDecryptedFile(decrypted) {
  const blob = new Blob([decrypted.fileBytes], {
    type: decrypted.meta.type || "application/octet-stream",
  });

  if (currentObjectUrl) {
    URL.revokeObjectURL(currentObjectUrl);
  }
  currentObjectUrl = URL.createObjectURL(blob);

  window.location.href = currentObjectUrl;
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "red" : "var(--ink-soft)";
}
