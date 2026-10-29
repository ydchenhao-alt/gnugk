let csrf = "";
let state = null;
const $ = (id) => document.getElementById(id);
function toast(msg) { const t = $("toast"); t.textContent = msg; t.style.display = "block"; setTimeout(() => t.style.display = "none", 4000); }
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "X-Requested-With": "XMLHttpRequest", "X-CSRF-Token": csrf, "Content-Type": "application/json" }, ...opts });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { showLogin(); throw new Error("未登录"); }
  if (!r.ok) throw new Error(j.error || ("请求失败 " + r.status));
  return j;
}
function showLogin() { $("login").style.display = "block"; $("app").style.display = "none"; }
function showApp() { $("login").style.display = "none"; $("app").style.display = "flex"; }
async function init() {
  try { const me = await api("/api/me"); csrf = me.csrf; showApp(); await refreshAll(); }
  catch { showLogin(); }
}
$("loginBtn").onclick = async () => {
  try {
    const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: $("pw").value }) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || "登录失败");
    csrf = j.csrf; showApp(); await refreshAll();
  } catch (e) { $("loginErr").textContent = e.message; }
};
$("pw").addEventListener("keydown", (e) => { if (e.key === "Enter") $("loginBtn").click(); });
$("logoutBtn").onclick = async () => { try { await api("/api/logout", { method: "POST", body: "{}" }); } catch {} csrf = ""; showLogin(); };
document.querySelectorAll(".side button[data-page]").forEach((b) => b.onclick = () => {
  document.querySelectorAll(".side button[data-page]").forEach((x) => x.classList.remove("on"));
  b.classList.add("on");
  document.querySelectorAll("main section").forEach((s) => s.style.display = "none");
  $("page-" + b.dataset.page).style.display = "block";
  $("pageTitle").textContent = b.textContent;
  if (b.dataset.page === "net") loadNet();
  if (b.dataset.page === "fw") loadFw();
  if (b.dataset.page === "cfg") loadCfg();
  if (b.dataset.page === "sys") loadSys();
});
async function doAction(action, target, label) {
  if (!confirm(`确认执行：${label}${target ? "（" + target + "）" : ""}？`)) return;
  try { const j = await api("/api/action", { method: "POST", body: JSON.stringify({ action, target }) }); toast("已执行：" + label); await refreshAll(); }
  catch (e) { toast("失败：" + e.message); }
}
function renderEps() {
  const q = ($("epSearch").value || "").toLowerCase();
  const rows = (state.endpoints || []).filter((e) => (e.alias + " " + (e.address || "") + " " + e.raw).toLowerCase().includes(q));
  $("epTable").innerHTML = rows.length ? "<table><tr><th>别名</th><th>地址</th><th>原始行</th><th>操作</th></tr>" + rows.map((e) => `<tr><td>${esc(e.alias || "–")}</td><td>${esc(e.address || "–")}</td><td class="mono">${esc(e.raw)}</td><td><button onclick="doAction('unregister_alias','${esc(e.alias || "")}','注销终端')">注销</button>${e.address ? ` <button onclick="doAction('unregister_ip','${esc(e.address.split(":")[0])}','按 IP 注销')">按 IP 注销</button>` : ""}</td></tr>`).join("") + "</table>" : "<p class='muted'>暂无注册终端。</p>";
}
function renderCalls() {
  const rows = state.calls || [];
  const table = (rs) => rs.length ? "<table><tr><th>呼叫</th><th>原始行</th><th>操作</th></tr>" + rs.map((c) => `<tr><td>${esc(c.number || "–")}</td><td class="mono">${esc(c.raw)}</td><td>${c.number ? `<button onclick="doAction('disconnect_call','${esc(c.number)}','挂断通话')">挂断</button>` : ""}</td></tr>`).join("") + "</table>" : "<p class='muted'>当前无通话。</p>";
  $("callTable").innerHTML = table(rows);
  $("dashCalls").innerHTML = table(rows);
}
async function refreshAll() {
  try {
    state = await api("/api/state");
    $("gkPill").textContent = state.gk_online ? "网闸状态：在线" : "网闸状态：离线";
    $("gkPill").className = "pill " + (state.gk_online ? "ok" : "bad");
    $("sampled").textContent = state.sampled_at ? ("采样：" + state.sampled_at) : "";
    $("cEps").textContent = state.endpoint_count ?? "–";
    $("cCalls").textContent = state.call_count ?? "–";
    $("cTerm").textContent = (state.stats && state.stats.terminals != null ? state.stats.terminals : "–") + " / " + (state.stats && state.stats.gateways != null ? state.stats.gateways : "–");
    $("ratesNote").textContent = state.rates_note || "";
    renderEps(); renderCalls();
  } catch (e) { /* 登录态失效时 api() 已切到登录页 */ }
}
$("refreshBtn").onclick = refreshAll;
$("epSearch").oninput = renderEps;
$("unregAllBtn").onclick = () => doAction("unregister_all", "", "注销全部终端");
$("discAllBtn").onclick = () => doAction("disconnect_all", "", "断开全部通话");
$("reloadBtn").onclick = () => doAction("reload", "", "重载配置");
async function loadNet() { try { const j = await api("/api/network"); $("netAddr").textContent = j.ip_addr; $("netRoute").textContent = j.ip_route; } catch (e) { toast(e.message); } }
async function loadFw() { try { const j = await api("/api/firewall"); $("fwTable").innerHTML = "<table><tr><th>端口</th><th>协议</th><th>用途</th><th>范围</th></tr>" + j.ports.map((p) => `<tr><td>${esc(p.port)}</td><td>${esc(p.proto)}</td><td>${esc(p.use)}</td><td>${esc(p.scope)}</td></tr>`).join("") + "</table>"; $("fwRules").textContent = j.ruleset; } catch (e) { toast(e.message); } }
async function loadCfg() {
  try {
    const j = await api("/api/config");
    if (!j.exists) { $("cfgForm").innerHTML = "<p class='muted'>未找到配置文件：" + esc(j.path) + "。请先在目标机部署 gatekeeper.ini。</p>"; return; }
    let html = "";
    for (const [sec, fields] of Object.entries(j.editable)) {
      html += `<h3>[${esc(sec)}]</h3>`;
      for (const [f, [label, hint]] of Object.entries(fields)) {
        const key = sec + "." + f, val = j.values[key] ?? "";
        html += `<div class="field"><label>${esc(label)}（${esc(f)}）</label><input data-cfg="${esc(key)}" value="${esc(val)}"><small>${esc(hint)}</small></div>`;
      }
    }
    $("cfgForm").innerHTML = html;
  } catch (e) { toast(e.message); }
}
$("saveCfgBtn").onclick = async () => {
  const values = {};
  document.querySelectorAll("[data-cfg]").forEach((el) => { if (el.value !== "") values[el.dataset.cfg] = el.value; });
  if (!confirm("确认保存配置？保存前会自动备份旧配置，保存后 reload（只影响新呼叫）。")) return;
  try { const j = await api("/api/config", { method: "POST", body: JSON.stringify({ values }) }); toast("已保存，备份：" + j.backup); } catch (e) { toast("保存失败：" + e.message); }
};
async function loadSys() {
  try {
    const s = await api("/api/services");
    $("svcTable").innerHTML = "<table><tr><th>服务</th><th>状态</th></tr>" + Object.entries(s).filter(([k]) => !["gnugk_instances", "single_instance_ok"].includes(k)).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("") + `<tr><td>gnugk 实例数（应为 1）</td><td>${esc(s.gnugk_instances)}${s.single_instance_ok ? " ✓" : " ⚠ 有孤儿进程，请 pkill 后重起"}</td></tr></table>`;
    const l = await api("/api/logs"); $("actLog").textContent = l.actions_log; $("gkLog").textContent = l.gk_log;
  } catch (e) { toast(e.message); }
}
$("restartGkBtn").onclick = async () => { if (!confirm("确认重启 gnugk？进行中通话会中断。")) return; try { await api("/api/service", { method: "POST", body: JSON.stringify({ service: "gnugk", op: "restart" }) }); toast("已发送重启 gnugk"); } catch (e) { toast(e.message); } };
$("restartWebBtn").onclick = async () => { if (!confirm("确认重启管理台本身？页面会短暂断开，刷新后恢复。")) return; try { await api("/api/service", { method: "POST", body: JSON.stringify({ service: "gnugk-web", op: "restart" }) }); toast("已发送重启管理台"); } catch (e) { toast(e.message); } };
$("changePwBtn").onclick = async () => {
  try { const j = await api("/api/change-password", { method: "POST", body: JSON.stringify({ current: $("oldPw").value, new: $("newPw").value, confirm: $("newPw2").value }) }); toast(j.note); csrf = ""; showLogin(); }
  catch (e) { toast("改密失败：" + e.message); }
};
setInterval(() => { if ($("app").style.display !== "none") refreshAll(); }, 30000);
init();
