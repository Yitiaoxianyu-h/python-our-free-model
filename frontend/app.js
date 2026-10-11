(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const state = { summary: null, keyRevealed: false };

  const AIO = (label, hint) => `<div class="cart"></div>`;

  function toast(message) {
    const el = $("#toast");
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.remove("show"), 2200);
  }

  async function api(path, options) {
    const res = await fetch(path, options);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
    if (!res.ok) throw new Error((data && data.error && (data.error.message || data.error)) || `HTTP ${res.status}`);
    return data;
  }

  // ── 导航 ──────────────────────────────────────────────────────────────────
  function bindNav() {
    $$("#nav button").forEach(btn => {
      btn.addEventListener("click", () => {
        $$("#nav button").forEach(b => b.classList.toggle("active", b === btn));
        $$(".page").forEach(p => p.classList.toggle("active", p.id === `page-${btn.dataset.page}`));
        if (btn.dataset.page === "usage") loadStats();
        if (btn.dataset.page === "playground") renderPlayground();
        if (btn.dataset.page === "channels") renderChannels();
        if (btn.dataset.page === "eac") renderEac();
        if (btn.dataset.page === "logs") renderLogs();
      });
    });
    $("#goto-access").addEventListener("click", () => $('[data-page="access"]').click());
  }

  // ── 概览 ──────────────────────────────────────────────────────────────────
  function statusPill(status) {
    const map = {
      available: ["ok", "可用"],
      "region-blocked": ["warn", "地区受限"],
      unavailable: ["bad", "不可用"],
      unknown: ["muted", "未判定"],
    };
    const [cls, label] = map[status] || ["muted", status || "—"];
    return `<span class="pill ${cls}">${label}</span>`;
  }

  function channelOf(entry) {
    if (entry.channel === "kilo") return "Kilo";
    if (entry.channel === "eac") return "EAC";
    return "免费车道";
  }

  function renderSummary() {
    const s = state.summary;
    if (!s) return;
    const c = s.counts;
    $("#overview-cards").innerHTML = [
      card("可用模型", c.available, `共发现 ${c.total} 个`),
      card("地区受限", c.regionBlocked, "切换出口后可解锁"),
      card("调用次数", s.stats.requests, `失败 ${s.stats.failedRequests} 次`),
      card("输出 Token", fmt(s.stats.totals.output), `输入 ${fmt(s.stats.totals.input)}`),
    ].join("");
    $("#overview-meta").textContent =
      `版本 ${s.version} · 最近探测 ${time(s.probedAt)} · 目录同步 ${time(s.settings.catalogSyncedAt)}` +
      (s.egress ? ` · 出口 IP ${s.egress.ip}${s.egress.country ? " (" + s.egress.country + ")" : ""}` : "");
    $("#base-url").textContent = location.origin + "/v1";
    $("#access-base").textContent = location.origin + "/v1";
    updateCurlExample();
  }

  function card(label, value, sub) {
    return `<div class="card"><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub || ""}</div></div>`;
  }

  function fmt(n) {
    n = Number(n || 0);
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
    return String(n);
  }

  function time(ms) {
    if (!ms) return "—";
    const d = new Date(Number(ms));
    return `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  }

  // ── 模型清单 ─────────────────────────────────────────────────────────────
  function renderModels() {
    const s = state.summary;
    if (!s) return;
    const q = $("#model-search").value.trim().toLowerCase();
    const ch = $("#model-filter").value;
    const st = $("#model-status").value;
    const rows = s.catalog.filter(e => {
      if (q && !(`${e.name} ${e.id}`.toLowerCase().includes(q))) return false;
      if (ch && (e.channel || "free") !== ch) return false;
      if (st && e.availability !== st) return false;
      return true;
    });
    $("#models-body").innerHTML = rows.length === 0
      ? `<tr><td colspan="6" class="spinner">没有匹配的模型</td></tr>`
      : rows.map(e => `
        <tr>
          <td>${escapeHtml(e.name)}</td>
          <td class="mono" style="font-size:12px;color:var(--muted)">${escapeHtml(e.id)}</td>
          <td>${channelOf(e)}</td>
          <td class="note">${e.vision ? "视觉+文本" : "文本"} · ${Math.round((e.contextWindow || 0) / 1024)}K</td>
          <td>${statusPill(e.availability)}</td>
          <td><button class="btn" data-copy-text="${escapeAttr(e.id)}">复制 ID</button></td>
        </tr>`).join("");
  }

  function escapeHtml(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
  }
  function escapeAttr(v) { return escapeHtml(v).replace(/"/g, "&quot;"); }

  // ── 渠道 / EAC ───────────────────────────────────────────────────────────
  const LOGIN_LABEL = {
    none: "免密直连", browser: "浏览器登录", "device-code": "设备码登录",
    sms: "短信验证码", captcha: "验证码", pending: "待定",
  };
  async function renderChannels() {
    try {
      const data = await api("/api/management/channels");
      $("#channels-grid").innerHTML = data.channels.map(c => {
        const canLogin = c.implemented && !["anonymous", "kilo"].includes(c.id);
        const st = c.loginState || {};
        const loginNote = st.status === "pending" ? "登录进行中…"
          : st.status === "ok" ? "已登录" : st.status === "error" ? ("登录失败：" + escapeHtml(st.message || "")) : "";
        let flow = "";
        if (st.status === "awaiting-code") {
          flow = `<div class="note" style="margin-top:8px">${escapeHtml(st.hint || "请完成验证后提交")}</div>`
            + (st.qr ? `<img src="${escapeAttr(st.qr)}" alt="QR" style="margin-top:8px;width:150px;height:150px;background:#fff;border-radius:8px" />` : "")
            + `<div class="row" style="margin-top:8px"><input type="text" data-login-input="${escapeAttr(c.id)}" placeholder="${st.needPhone ? "手机号" : "验证码"}" /><button class="btn primary" data-login-submit="${escapeAttr(c.id)}">提交</button></div>`;
        }
        return `
        <div class="card">
          <div class="label">${escapeHtml(c.vendor)}</div>
          <div style="font-weight:700;margin:6px 0">${escapeHtml(c.name)}</div>
          <div class="note">登录方式：${LOGIN_LABEL[c.login] || c.login}</div>
          <div style="margin-top:8px">${c.implemented
            ? '<span class="pill ok">已接入</span>'
            : '<span class="pill muted">待移植</span>'}</div>
          ${c.accounts ? `<div class="note" style="margin-top:6px">账号 ${c.accounts} 个 / 启用 ${c.enabledAccounts}</div>` : ""}
          ${loginNote ? `<div class="note" style="margin-top:6px">${loginNote}</div>` : ""}
          ${flow}
          ${canLogin ? `<div style="margin-top:10px"><button class="btn primary" data-login="${escapeAttr(c.id)}">登录 / 新建账号</button></div>` : ""}
        </div>`;
      }).join("");
    } catch (e) { toast(e.message); }
    renderAccounts();
  }

  async function renderAccounts() {
    try {
      const data = await api("/api/management/accounts");
      const rows = data.accounts || [];
      $("#accounts-body").innerHTML = rows.length === 0
        ? `<tr><td colspan="5" class="spinner">暂无账号</td></tr>`
        : rows.map(a => `<tr>
            <td>${escapeHtml(a.provider)}</td>
            <td>${escapeHtml(a.nickname || a.id)}</td>
            <td>${a.hasCredential ? '<span class="pill ok">已保存</span>' : '<span class="pill bad">缺失</span>'}</td>
            <td><label class="switch"><input type="checkbox" data-acc-enable="${escapeAttr(a.id)}" ${a.enabled ? "checked" : ""} /></label></td>
            <td><button class="btn" data-acc-del="${escapeAttr(a.id)}">删除</button></td>
          </tr>`).join("");
    } catch (e) { /* 静默 */ }
  }

  async function toggleAccount(id, enabled) {
    try { await api(`/api/management/accounts/${id}/enabled`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled }) }); toast(enabled ? "已启用" : "已停用"); }
    catch (e) { toast(e.message); }
  }

  async function deleteAccount(id) {
    if (!confirm("删除该账号及其本机凭据？")) return;
    try { await api(`/api/management/accounts/${id}/delete`, { method: "POST" }); toast("已删除"); await renderChannels(); await loadSummary(); }
    catch (e) { toast(e.message); }
  }

  async function submitChannelLogin(channelId, value) {
    if (!value) { toast("请输入验证码"); return; }
    try {
      const res = await api(`/api/management/channels/${channelId}/login/submit`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: value, phone: value }),
      });
      if (res.error) { toast(res.error); return; }
      if (res.status === "ok") { toast("登录成功，账号已保存"); await renderChannels(); await loadSummary(); }
      else { toast("已提交，请继续完成验证"); await renderChannels(); }
    } catch (e) { toast(e.message); }
  }

  async function startChannelLogin(channelId, button) {
    button.disabled = true;
    button.textContent = "已发起，请完成浏览器授权…";
    try {
      const res = await api(`/api/management/channels/${channelId}/login`, { method: "POST" });
      if (res.error) { toast(res.error); button.disabled = false; button.textContent = "登录 / 新建账号"; return; }
      toast("已尝试打开浏览器，完成后自动保存");
      let tries = 0;
      const timer = setInterval(async () => {
        tries += 1;
        try {
          const st = await api(`/api/management/channels/${channelId}/login`);
          if (st.status === "ok") {
            clearInterval(timer); toast("登录成功，账号已保存"); await renderChannels(); await loadSummary();
          } else if (st.status === "error" || tries > 60) {
            clearInterval(timer); toast(st.message || "登录超时"); button.disabled = false; button.textContent = "登录 / 新建账号";
          }
        } catch { /* 继续轮询 */ }
      }, 2000);
    } catch (e) {
      toast(e.message); button.disabled = false; button.textContent = "登录 / 新建账号";
    }
  }
  async function renderEac() {
    try {
      const s = await api("/api/management/eac");
      $("#eac-cards").innerHTML = [
        card("车道", s.laneAvailable ? "可用" : "不可用",
             s.laneAvailable ? (s.mode || "—") : "密封凭据无法解锁"),
        card("授权", s.authorized ? "已授权" : "未授权",
             s.login ? `@${s.login}${s.starred ? " · 已 star" : " · 未 star"}` : "点下面的按钮用 GitHub 授权"),
        card("渠道模型", s.modelsInCatalog, s.laneAvailable ? "来自 EAC 网关" : "车道不可用"),
      ].join("");
      if (s.repo) $("#eac-repo").textContent = s.repo;
      $("#eac-auth-meta").textContent = s.authorized
        ? `已授权：@${s.login}${s.starred ? "（已 star）" : "（未 star，网关通常仍会拒绝）"} · 于 ${time(s.verifiedAt)}`
        : "尚未授权。";
      $("#eac-gateway-meta").textContent = `${s.mode || "—"} · ${s.base || "—"}`
        + (s.customGateway ? "（自建网关）" : "")
      $("#eac-mode").value = s.mode === "direct" ? "direct" : "worker";
      toggleEacModeFields();
    } catch (e) { toast(e.message); }
  }

  let eacLoginTimer = null;

  async function startEacLogin() {
    if (eacLoginTimer) { clearInterval(eacLoginTimer); eacLoginTimer = null; }
    try {
      const started = await api("/api/management/eac/login/start", { method: "POST" });
      if (started.error) { toast(started.error); return; }
      const link = started.link;
      const a = $("#eac-login-link");
      a.href = started.url; a.style.display = "";
      $("#eac-auth-meta").textContent = started.opened
        ? "已打开浏览器，请在页面上完成 GitHub 登录并 star 仓库…"
        : "请点「打开授权页」完成 GitHub 登录并 star 仓库…";
      let tries = 0;
      eacLoginTimer = setInterval(async () => {
        tries += 1;
        try {
          const r = await api(`/api/management/eac/login/poll?link=${encodeURIComponent(link)}`);
          if (r.status === "ok") {
            clearInterval(eacLoginTimer); eacLoginTimer = null;
            a.style.display = "none";
            toast(`授权成功：@${r.login}`); await renderEac(); await loadSummary(); return;
          }
          if (r.status === "unstarred") {
            $("#eac-auth-meta").textContent = `已登录 GitHub（@${r.login}），但还没有 star ${r.repo || "本仓库"}；star 后本页会自动完成。`;
          } else if (r.status === "expired") {
            clearInterval(eacLoginTimer); eacLoginTimer = null;
            $("#eac-auth-meta").textContent = "授权链接已过期，请重新点击「用 GitHub 授权」。";
          } else if (r.error) {
            $("#eac-auth-meta").textContent = `等待授权…（${r.error}）`;
          } else {
            $("#eac-auth-meta").textContent = "等待你在浏览器中完成授权…";
          }
        } catch { /* 继续轮询 */ }
        if (tries > 90) { clearInterval(eacLoginTimer); eacLoginTimer = null; $("#eac-auth-meta").textContent = "授权超时，请重新点击「用 GitHub 授权」。"; }
      }, 2000);
    } catch (e) { toast(e.message); }
  }

  function toggleEacModeFields() {
    const worker = $("#eac-mode").value !== "direct";
    $("#eac-signkey-field").style.display = worker ? "" : "none";
    $("#eac-apikey-field").style.display = worker ? "none" : "";
  }

  async function saveEacGateway() {
    const models = $("#eac-models").value.split(/[,，\n]/).map(x => x.trim()).filter(Boolean);
    const body = { mode: $("#eac-mode").value, base: $("#eac-base").value.trim(), models };
    if (body.mode === "worker") body.signKey = $("#eac-signkey").value.trim();
    else body.apiKey = $("#eac-apikey").value.trim();
    try {
      const res = await api("/api/management/eac/gateway", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      if (res.error) { toast(res.error); return; }
      toast("网关配置已保存"); await renderEac(); await loadSummary();
    } catch (e) { toast(e.message); }
  }

  // ── 用量 ──────────────────────────────────────────────────────────────────
  async function loadStats() {
    try {
      const s = await api("/api/management/stats");
      const t = s.totals;
      $("#usage-cards").innerHTML = [
        card("总请求", t.requests, `失败 ${t.failedRequests}`),
        card("对话回合", t.logical.turns, `已恢复 ${t.logical.recovered}`),
        card("输出 Token", fmt(t.totals.output), `思考 ${fmt(t.totals.reasoning)}`),
        card("缓存命中", fmt(t.totals.cacheRead), ""),
      ].join("");
      const models = (s.models || []).sort((a, b) => (b.output || 0) - (a.output || 0));
      $("#usage-models").innerHTML = models.length === 0
        ? `<tr><td colspan="6" class="spinner">暂无数据</td></tr>`
        : models.map(m => `<tr>
            <td class="mono" style="font-size:12px">${escapeHtml(m.model)}</td>
            <td>${fmt(m.input)}</td><td>${fmt(m.output)}</td><td>${fmt(m.reasoning)}</td>
            <td>${m.calls}</td><td>${m.failed}</td>
          </tr>`).join("");
    } catch (e) { toast(e.message); }
  }

  // ── 在线游乐场 ────────────────────────────────────────────────────────────
  const pg = { history: [], controller: null, sending: false, filledFor: null };

  function pgEntry() {
    const id = $("#pg-model") ? $("#pg-model").value : "";
    const s = state.summary;
    if (!s || !id) return null;
    return (s.catalog || []).find(e => e.id === id) || null;
  }

  function pgEffortsFor(entry) {
    if (!entry) return [];
    if (Array.isArray(entry.efforts) && entry.efforts.length) {
      const names = { disabled: "关闭思考", low: "低", medium: "中", high: "高", max: "最大" };
      return entry.efforts.map(x => ({ id: x, name: names[x] || x }));
    }
    if (entry.reasoning) {
      return [{ id: "light", name: "精简" }, { id: "balanced", name: "均衡" }, { id: "deep", name: "深思" }];
    }
    return [];
  }

  function renderPlayground() {
    const sel = $("#pg-model");
    const s = state.summary;
    if (!sel || !s) return;
    const rows = (s.catalog || []).filter(e => e.availability !== "unavailable");
    const current = sel.value;
    const tag = e => (e.channel === "eac" ? "[EAC] " : e.channel === "kilo" ? "[Kilo] " : "");
    sel.innerHTML = rows.map(e => `<option value="${escapeAttr(e.id)}">${escapeHtml(tag(e) + e.name)}</option>`).join("");
    if (current && rows.some(e => e.id === current)) sel.value = current;
    else if (rows.length) sel.value = rows[0].id;
    applyPlaygroundModel();
    // 正在流式回复时不要重建对话区，否则会打断输出。
    if (!pg.sending) pgRebuild();
  }

  function applyPlaygroundModel(force) {
    const entry = pgEntry();
    const meta = $("#pg-model-meta");
    if (!entry) { if (meta) meta.textContent = "没有可用模型，请先刷新清单。"; return; }
    const ctx = Math.round((entry.contextWindow || 0) / 1024);
    const outMax = entry.maxOutput || 32768;
    if (meta) {
      meta.textContent = `${entry.id} · 上下文 ${ctx}K · 输出上限 ${outMax} · ${entry.vision ? "支持图片" : "纯文本"} · ${entry.reasoning ? "支持思考" : "无思考"}`;
    }
    // 只在该模型的参数还没填过（或用户主动切模型）时才覆盖输入，避免后台刷新冲掉用户改动。
    if (!force && pg.filledFor === entry.id) return;
    pg.filledFor = entry.id;
    const mt = $("#pg-maxtokens");
    if (mt) {
      const fallback = (state.summary && state.summary.settings && state.summary.settings.defaultMaxTokens) || 32768;
      mt.value = Math.min(outMax, fallback);
    }
    const eff = $("#pg-effort");
    const field = $("#pg-effort-field");
    if (eff && field) {
      const list = pgEffortsFor(entry);
      if (list.length === 0) { field.style.display = "none"; eff.innerHTML = ""; }
      else {
        field.style.display = "";
        eff.innerHTML = list.map(o => `<option value="${escapeAttr(o.id)}">${escapeHtml(o.name)}</option>`).join("");
        const def = entry.effortDefault || (Array.isArray(entry.efforts) ? entry.efforts[0] : "balanced");
        if (list.some(o => o.id === def)) eff.value = def;
      }
    }
  }

  function pgMessageNode(role, content, reasoning, open) {
    const wrap = document.createElement("div");
    wrap.className = `msg ${role}`;
    const who = document.createElement("div");
    who.className = "who";
    who.textContent = role === "user" ? "我" : "助手";
    wrap.appendChild(who);
    if (reasoning) {
      const details = document.createElement("details");
      details.className = "reasoning-box";
      if (open) details.open = true;
      const summary = document.createElement("summary");
      summary.textContent = `思考链（${reasoning.length} 字）`;
      const body = document.createElement("div");
      body.className = "reasoning";
      body.textContent = reasoning;
      details.appendChild(summary);
      details.appendChild(body);
      wrap.appendChild(details);
    }
    const body = document.createElement("div");
    body.className = "body";
    body.textContent = content;
    wrap.appendChild(body);
    return wrap;
  }

  function pgRebuild() {
    const box = $("#pg-chat");
    if (!box) return;
    box.innerHTML = pg.history.length === 0
      ? `<div class="note" style="padding:8px 2px">在下面输入消息开始对话。切换模型会自动套用它的上下文与推理配置。</div>`
      : "";
    // 历史里的思考链用可折叠节点重建，随时可点开查看。
    for (const m of pg.history) box.appendChild(pgMessageNode(m.role, m.content, m.reasoning, false));
  }

  async function sendPlayground() {
    if (pg.sending) return;
    const input = $("#pg-input");
    const text = (input.value || "").trim();
    const model = $("#pg-model") ? $("#pg-model").value : "";
    if (!model) { toast("请先选择模型"); return; }
    if (!text) { toast("请输入内容"); return; }

    const messages = [];
    const system = $("#pg-system") ? $("#pg-system").value.trim() : "";
    if (system) messages.push({ role: "system", content: system });
    for (const m of pg.history) messages.push({ role: m.role, content: m.content });
    messages.push({ role: "user", content: text });

    pg.history.push({ role: "user", content: text });
    pgRebuild();
    input.value = "";
    pg.sending = true;
    if ($("#btn-pg-send")) $("#btn-pg-send").disabled = true;
    if ($("#btn-pg-stop")) $("#btn-pg-stop").style.display = "";

    const box = $("#pg-chat");
    const bubble = pgMessageNode("assistant", "", "", false);
    box.appendChild(bubble);
    const body = bubble.querySelector(".body");
    const textNode = document.createTextNode("");
    const cursor = document.createElement("span");
    cursor.className = "cursor";
    body.appendChild(textNode);
    body.appendChild(cursor);
    // 思考链：流式时实时展开，结束后折叠成一个随时可点开的「思考链」。
    let reasonBox = null, reasonText = null, reasonSum = null;
    function ensureReasonBox() {
      if (reasonBox) return;
      reasonBox = document.createElement("details");
      reasonBox.className = "reasoning-box";
      reasonBox.open = true;
      reasonSum = document.createElement("summary");
      reasonText = document.createElement("div");
      reasonText.className = "reasoning";
      reasonBox.appendChild(reasonSum);
      reasonBox.appendChild(reasonText);
      bubble.insertBefore(reasonBox, body);
    }
    box.scrollTop = box.scrollHeight;

    const effortVisible = $("#pg-effort-field") && $("#pg-effort-field").style.display !== "none";
    const controller = new AbortController();
    pg.controller = controller;
    let acc = "", accReason = "", usage = null, errMsg = "";
    try {
      const res = await fetch("/api/management/playground/chat", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model, messages,
          temperature: Number($("#pg-temp").value),
          max_tokens: Number($("#pg-maxtokens").value) || undefined,
          reasoning_effort: (effortVisible && $("#pg-effort").value) || undefined,
        }),
        signal: controller.signal,
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try { const d = await res.json(); msg = (d && d.error && (d.error.message || d.error)) || msg; } catch { /* 忽略 */ }
        throw new Error(msg);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          for (const line of block.split("\n")) {
            if (!line.startsWith("data:")) continue;
            const raw = line.slice(5).trim();
            if (raw === "" || raw === "[DONE]") continue;
            let evt;
            try { evt = JSON.parse(raw); } catch { continue; }
            if (evt.delta) { acc += evt.delta; textNode.textContent = acc; box.scrollTop = box.scrollHeight; }
            else if (evt.reasoning) { accReason += evt.reasoning; ensureReasonBox(); reasonText.textContent = accReason; reasonSum.textContent = `思考中…（${accReason.length} 字）`; box.scrollTop = box.scrollHeight; }
            else if (evt.error) { errMsg = evt.error; }
            else if (evt.usage) { usage = evt.usage; }
            else if (evt.done) { if (evt.usage) usage = evt.usage; }
          }
        }
      }
    } catch (err) {
      if (err.name !== "AbortError") errMsg = errMsg || err.message;
    } finally {
      cursor.remove();
      pg.controller = null;
      pg.sending = false;
      if ($("#btn-pg-send")) $("#btn-pg-send").disabled = false;
      if ($("#btn-pg-stop")) $("#btn-pg-stop").style.display = "none";
    }

    if (reasonBox) {
      // 思考结束：折叠成可点击的「思考链」标题（点一下即可再次展开）。
      reasonBox.open = false;
      reasonSum.textContent = `思考链（${accReason.length} 字）`;
    }
    if (errMsg) bubble.classList.add("error");
    if (acc === "" && errMsg) textNode.textContent = errMsg;
    if (usage) {
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = `输入 ${usage.prompt_tokens || 0} · 输出 ${usage.completion_tokens || 0} · 总 ${usage.total_tokens || 0}`;
      bubble.appendChild(meta);
    }
    if (acc || accReason) pg.history.push({ role: "assistant", content: acc, reasoning: accReason });
    box.scrollTop = box.scrollHeight;
  }

  function stopPlayground() {
    if (pg.controller) pg.controller.abort();
  }

  function clearPlayground() {
    pg.history = [];
    pgRebuild();
  }

  // ── 日志 ──────────────────────────────────────────────────────────────────
  function logError(r) {
    if (r.error) return `<span title="${escapeAttr(r.error)}">${escapeHtml(r.error)}</span>`;
    if (r.code) return `<span class="note">${escapeHtml(r.code)}</span>`;
    return "";
  }

  async function renderLogs() {
    const params = new URLSearchParams();
    const model = $("#log-model") ? $("#log-model").value : "";
    if (model) params.set("model", model);
    if ($("#log-errors") && $("#log-errors").checked) params.set("errors", "1");
    params.set("limit", "200");
    try {
      const data = await api(`/api/management/logs?${params.toString()}`);
      const sel = $("#log-model");
      if (sel) {
        const current = sel.value;
        sel.innerHTML = `<option value="">全部模型</option>`
          + (data.models || []).map(m => `<option value="${escapeAttr(m.id)}">${escapeHtml(m.id)}（${m.count}）</option>`).join("");
        sel.value = current;
      }
      $("#logs-meta").textContent =
        `保留最近 ${data.stored}/${data.limit} 条 · 失败 ${data.failed} 条 · 当前筛选 ${data.total} 条`;
      const rows = data.items || [];
      $("#logs-body").innerHTML = rows.length === 0
        ? `<tr><td colspan="10" class="spinner">暂无日志</td></tr>`
        : rows.map(r => `
        <tr data-log="${r.id}" style="cursor:pointer">
          <td class="note">${time(r.at)}</td>
          <td class="mono" style="font-size:12px">${escapeHtml(r.model)}</td>
          <td>${escapeHtml(r.channel || "")}${r.stream ? ' <span class="note">流</span>' : ""}</td>
          <td>${r.ok ? '<span class="pill ok">成功</span>' : `<span class="pill bad">${r.status || 502}</span>`}</td>
          <td class="note">${r.latencyMs != null ? r.latencyMs + "ms" : "—"}</td>
          <td class="note">${r.ttftMs != null ? r.ttftMs + "ms" : "—"}</td>
          <td>${fmt(r.input)}</td>
          <td>${fmt(r.output)}</td>
          <td class="note" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${logError(r)}</td>
          <td><button class="btn" data-log-toggle="${r.id}">详情</button></td>
        </tr>`).join("");
    } catch (e) { toast(e.message); }
  }

  async function toggleLogDetail(id, btn) {
    const existing = document.querySelector(`tr[data-log-detail="${id}"]`);
    if (existing) {
      existing.remove();
      if (btn) btn.textContent = "详情";
      return;
    }
    try {
      const r = await api(`/api/management/logs/${id}`);
      const tr = document.createElement("tr");
      tr.setAttribute("data-log-detail", id);
      tr.innerHTML = `<td colspan="10">
        <div class="note" style="margin-bottom:6px">请求（${escapeHtml(r.model)} · ${r.stream ? "流式" : "非流式"}）</div>
        <pre class="mono note" style="white-space:pre-wrap;margin:0 0 10px;max-height:240px;overflow:auto">${escapeHtml(r.request || "(空)")}</pre>
        ${r.error ? `<div class="note" style="margin-bottom:10px">错误：${escapeHtml(r.errorType || "")} ${escapeHtml(r.error)}</div>` : ""}
        <div class="note" style="margin-bottom:6px">响应</div>
        <pre class="mono note" style="white-space:pre-wrap;margin:0;max-height:240px;overflow:auto">${escapeHtml(r.response || "(空)")}</pre>
      </td>`;
      const row = document.querySelector(`tr[data-log="${id}"]`);
      if (row) row.after(tr); else $("#logs-body").appendChild(tr);
      if (btn) btn.textContent = "收起";
    } catch (e) { toast(e.message); }
  }

  // ── 设置 ──────────────────────────────────────────────────────────────────
  function fillSettings() {
    const st = state.summary && state.summary.settings;
    if (!st) return;
    $("#set-enabled").checked = st.enabled;
    $("#set-forward").checked = st.forward.enabled;
    $("#set-region").checked = st.exposeRegionModels;
    $("#set-recovery").checked = st.streamRecovery;
    $("#set-interval").value = st.probeIntervalMinutes;
    $("#set-maxtokens").value = st.defaultMaxTokens;
    $("#set-egress").checked = st.egress.enabled;
    $("#set-egress-mode").value = st.egress.mode;
    $("#egress-meta").textContent = st.egress.hasUrl ? `已配置：${st.egress.urlLabel}` : "未配置代理地址";
    $("#set-lan").checked = st.forward.lan.enabled;
    $("#set-lan-port").value = st.forward.lan.port || 0;
    renderLanMeta(st.forward.lan);
    const km = $("#key-mode");
    if (km && document.activeElement !== km) km.value = st.forward.keyMode || "auto";
    toggleKeyModeFields();
    $("#settings-meta").textContent = `数据目录由启动参数决定 · 目录同步 ${time(st.catalogSyncedAt)}`;
  }

  function toggleKeyModeFields() {
    const mode = $("#key-mode") ? $("#key-mode").value : "auto";
    const box = $("#key-custom");
    if (box) box.style.display = mode === "custom" ? "" : "none";
    const meta = $("#key-mode-meta");
    if (meta) {
      meta.textContent = mode === "off"
        ? "当前不校验 API Key：任何客户端（含不填 Key）都能调用，请勿在公网暴露。"
        : mode === "custom" ? "使用你自定义的 API Key；保存后立即生效。"
        : "使用本机自动生成的 API Key（默认）。";
    }
  }

  async function saveKeyMode() {
    const mode = $("#key-mode").value;
    const custom = $("#key-custom") ? $("#key-custom").value.trim() : "";
    if (mode === "custom" && !custom) { toast("自定义模式下请填写 API Key"); return; }
    const body = { forwardKeyMode: mode };
    if (mode === "custom") body.forwardKey = custom;
    try {
      await api("/api/management/settings", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      toast("校验方式已保存");
      await loadSummary();
    } catch (e) { toast(e.message); }
  }

  function renderLanMeta(lan) {
    if (!lan || !lan.enabled) {
      $("#lan-meta").textContent = "未启用。启用后下方显示可拨通的局域网地址。";
      return;
    }
    const addrs = (lan.addresses || []);
    const base = addrs.length ? `http://${addrs[0]}:${lan.port}/v1` : "(未检测到局域网地址)";
    $("#lan-meta").innerHTML = lan.running
      ? `运行中：<span class="mono">${base}</span>` + (addrs.length > 1 ? ` （其它地址：${addrs.slice(1).join(", ")}）` : "")
      : "未运行（端口可能被占用，或本机转发口已关闭）";
  }

  async function saveSettings() {
    const body = {
      enabled: $("#set-enabled").checked,
      exposeRegionModels: $("#set-region").checked,
      streamRecovery: $("#set-recovery").checked,
      probeIntervalMinutes: Number($("#set-interval").value) || 15,
      defaultMaxTokens: Number($("#set-maxtokens").value) || 32768,
      forward: {
        enabled: $("#set-forward").checked,
        lan: { enabled: $("#set-lan").checked, port: Number($("#set-lan-port").value) || 0 },
      },
      egress: { enabled: $("#set-egress").checked, mode: $("#set-egress-mode").value, url: $("#set-egress-url").value },
    };
    try {
      await api("/api/management/settings", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      toast("设置已保存");
      await loadSummary();
    } catch (e) { toast(e.message); }
  }

  // ── API 接入 ─────────────────────────────────────────────────────────────
  function updateCurlExample() {
    const base = location.origin + "/v1";
    $("#curl-example").textContent =
      `curl ${base}/chat/completions \\\n` +
      `  -H "Authorization: Bearer <你的 API Key>" \\\n` +
      `  -H "Content-Type: application/json" \\\n` +
      `  -d '{"model":"nemotron-3.5-lightning-free","messages":[{"role":"user","content":"你好"}],"stream":true}'`;
  }

  async function showKey() {
    if (state.keyRevealed) {
      $("#access-key").textContent = "••••••••";
      state.keyRevealed = false;
      $("#btn-show-key").textContent = "显示";
      return;
    }
    try {
      const data = await api("/api/management/forward/key");
      $("#access-key").textContent = data.key;
      state.keyRevealed = true;
      $("#btn-show-key").textContent = "隐藏";
    } catch (e) { toast(e.message); }
  }

  async function rotateKey() {
    if (!confirm("轮换密钥会使现有客户端配置立即失效，确定继续？")) return;
    try {
      const data = await api("/api/management/forward/rotate", { method: "POST" });
      $("#access-key").textContent = data.key;
      state.keyRevealed = true;
      $("#btn-show-key").textContent = "隐藏";
      toast("密钥已轮换");
    } catch (e) { toast(e.message); }
  }

  // ── 复制 ──────────────────────────────────────────────────────────────────
  function bindCopy() {
    document.addEventListener("click", async ev => {
      const loginBtn = ev.target.closest("[data-login]");
      if (loginBtn) { startChannelLogin(loginBtn.dataset.login, loginBtn); return; }
      const delBtn = ev.target.closest("[data-acc-del]");
      if (delBtn) { deleteAccount(delBtn.dataset.accDel); return; }
      const submitBtn = ev.target.closest("[data-login-submit]");
      if (submitBtn) {
        const id = submitBtn.dataset.loginSubmit;
        const input = document.querySelector(`[data-login-input="${id}"]`);
        submitChannelLogin(id, input ? input.value.trim() : "");
        return;
      }
      const secretBtn = ev.target.closest("[data-copy-secret]");
      if (secretBtn) {
        const lan = secretBtn.dataset.copySecret === "lan";
        try {
          const d = await api(lan ? "/api/management/forward/lan/key" : "/api/management/forward/key");
          await navigator.clipboard.writeText((d && d.key) || "");
          toast(lan ? "已复制中继 Key" : "已复制 API Key");
        } catch (err) { toast(err.message); }
        return;
      }
      const target = ev.target.closest("[data-copy]") || ev.target.closest("[data-copy-text]");
      if (!target) return;
      let text = target.dataset.copyText;
      if (!text && target.dataset.copy) text = $(target.dataset.copy).textContent;
      try { await navigator.clipboard.writeText(text); toast("已复制"); }
      catch { toast("复制失败，请手动选择"); }
    });
  }

  // ── 加载 ──────────────────────────────────────────────────────────────────
  async function loadSummary() {
    const s = await api("/api/management/summary");
    state.summary = s;
    renderSummary();
    renderModels();
    fillSettings();
    if ($("#page-channels").classList.contains("active")) renderChannels();
    if ($("#page-eac").classList.contains("active")) renderEac();
    if ($("#page-logs").classList.contains("active")) renderLogs();
    if ($("#page-playground").classList.contains("active")) renderPlayground();
  }

  function bindActions() {
    // 防御性绑定：任一元素缺失时只跳过它，不中断后续所有绑定
    // （曾因浏览器缓存旧 index.html + 新 app.js 导致整页交互失效）。
    const on = (sel, event, handler) => { const el = $(sel); if (el) el.addEventListener(event, handler); };
    document.addEventListener("change", ev => {
      const toggle = ev.target.closest("[data-acc-enable]");
      if (toggle) toggleAccount(toggle.dataset.accEnable, toggle.checked);
    });
    ["#model-search", "#model-filter", "#model-status"].forEach(sel => {
      on(sel, "input", renderModels);
      on(sel, "change", renderModels);
    });
    on("#btn-refresh", "click", async e => {
      e.target.disabled = true; e.target.textContent = "刷新中…";
      try { state.summary = await api("/api/management/refresh", { method: "POST" }); renderSummary(); renderModels(); toast("清单已刷新"); }
      catch (err) { toast(err.message); }
      finally { e.target.disabled = false; e.target.textContent = "刷新清单"; }
    });
    on("#btn-reprobe", "click", async e => {
      e.target.disabled = true; e.target.textContent = "探测中…";
      try { state.summary = await api("/api/management/reprobe", { method: "POST" }); renderSummary(); renderModels(); toast("探测完成"); }
      catch (err) { toast(err.message); }
      finally { e.target.disabled = false; e.target.textContent = "主动探测"; }
    });
    on("#btn-save-settings", "click", saveSettings);
    on("#btn-show-key", "click", showKey);
    on("#btn-rotate-key", "click", rotateKey);
    on("#btn-show-lan-key", "click", async () => {
      const el = $("#lan-key");
      if (el.dataset.revealed === "1") { el.textContent = "••••••••"; el.dataset.revealed = "0"; $("#btn-show-lan-key").textContent = "显示"; return; }
      try { const d = await api("/api/management/forward/lan/key"); el.textContent = d.key; el.dataset.revealed = "1"; $("#btn-show-lan-key").textContent = "隐藏"; }
      catch (e) { toast(e.message); }
    });
    on("#btn-rotate-lan-key", "click", async () => {
      if (!confirm("轮换中继 Key 后，局域网内其它设备需更新配置，继续？")) return;
      try { const d = await api("/api/management/forward/lan/rotate", { method: "POST" }); $("#lan-key").textContent = d.key; $("#lan-key").dataset.revealed = "1"; $("#btn-show-lan-key").textContent = "隐藏"; toast("中继 Key 已轮换"); }
      catch (e) { toast(e.message); }
    });
    on("#eac-mode", "change", toggleEacModeFields);
    on("#btn-eac-save", "click", saveEacGateway);
    on("#btn-eac-login", "click", startEacLogin);
    on("#btn-eac-clear", "click", async () => {
      if (!confirm("恢复使用内置密封凭据？（将删除自建网关配置）")) return;
      try { await api("/api/management/eac/gateway/clear", { method: "POST" }); toast("已恢复内置凭据"); await renderEac(); await loadSummary(); }
      catch (e) { toast(e.message); }
    });
    on("#btn-eac-pool", "click", async () => {
      try {
        const p = await api("/api/management/eac/pool");
        $("#eac-gateway-meta").textContent = `资源池读数：${JSON.stringify(p)}`;
        toast("已读取资源池");
      } catch (e) { toast(e.message); }
    });
    on("#btn-eac-logout", "click", async () => {
      try { await api("/api/management/eac/logout", { method: "POST" }); toast("已退出授权"); await renderEac(); }
      catch (e) { toast(e.message); }
    });
    on("#log-model", "change", renderLogs);
    on("#log-errors", "change", renderLogs);
    on("#btn-logs-refresh", "click", renderLogs);
    on("#btn-logs-clear", "click", async () => {
      if (!confirm("清空全部请求日志？")) return;
      try { await api("/api/management/logs/clear", { method: "POST" }); toast("日志已清空"); await renderLogs(); }
      catch (e) { toast(e.message); }
    });
    document.addEventListener("click", ev => {
      const btn = ev.target.closest("[data-log-toggle]");
      const row = ev.target.closest("tr[data-log]");
      if (!btn && !row) return;
      const id = btn ? btn.dataset.logToggle : row.dataset.log;
      toggleLogDetail(id, btn);
    });
    on("#key-mode", "change", toggleKeyModeFields);
    on("#btn-save-key-mode", "click", saveKeyMode);
    on("#pg-model", "change", () => applyPlaygroundModel(true));
    on("#btn-pg-refresh", "click", async e => {
      e.target.disabled = true; e.target.textContent = "刷新中…";
      try { await loadSummary(); renderPlayground(); toast("模型清单已刷新"); }
      catch (err) { toast(err.message); }
      finally { e.target.disabled = false; e.target.textContent = "刷新模型"; }
    });
    on("#btn-pg-clear", "click", clearPlayground);
    on("#btn-pg-send", "click", sendPlayground);
    on("#btn-pg-stop", "click", stopPlayground);
    on("#pg-input", "keydown", ev => {
      if (ev.key === "Enter" && !ev.shiftKey) { ev.preventDefault(); sendPlayground(); }
    });
  }

  async function boot() {
    bindNav();
    bindCopy();
    bindActions();
    try { await loadSummary(); } catch (e) { toast(e.message); }
    setInterval(() => { if (document.visibilityState === "visible") loadSummary().catch(() => {}); }, 15000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
