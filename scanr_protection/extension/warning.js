const p = new URLSearchParams(location.search);
const target = p.get("u") || "";
document.getElementById("verdict").textContent = p.get("v") || "risky";
document.getElementById("url").textContent = target;      // textContent => no XSS
document.getElementById("detail").textContent = p.get("d") || "";

document.getElementById("back").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "goback" });
});

document.getElementById("go").addEventListener("click", async () => {
  if (!/^https?:\/\//i.test(target)) return;
  if (!confirm("This site was flagged as dangerous. Open it anyway?")) return;
  await chrome.runtime.sendMessage({ type: "allow", url: target });
  location.replace(target);
});
