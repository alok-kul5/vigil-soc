// Alert queue, investigation view, approvals and traces.

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const api = async (path, opts) => {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || r.statusText);
  return body;
};
const VERDICT = { true_positive: "Malicious", benign_true_positive: "Benign (authorised)", false_positive: "False positive" };
const state = { incidents: [], current: null, poll: null };

const approverInput = $("#approver");
try { approverInput.value = localStorage.getItem("approver") || ""; } catch {}
approverInput.addEventListener("change", () => { try { localStorage.setItem("approver", approverInput.value); } catch {} });

async function loadHealth() {
  const h = await api("/api/health");
  $("#health").textContent = h.api_configured ? `${h.model} · local · live` : "read-only (model offline)";
  state.live = h.api_configured;
}

async function loadQueue() {
  state.incidents = await api("/api/incidents");
  $("#queue-count").textContent = `· ${state.incidents.length}`;
  $("#queue").innerHTML = state.incidents.map((i) => {
    const r = i.latest_run;
    const tag = i.running ? `<span class="pill">investigating…</span>`
      : r && r.verdict ? `<span class="verdict ${r.verdict}">${VERDICT[r.verdict]}</span>${r.pending_actions ? `<span class="pill">${r.pending_actions} awaiting approval</span>` : ""}`
      : `<span class="pill">new</span>`;
    return `<li data-id="${i.id}" class="${state.current === i.id ? "active" : ""}">
      <span class="t">${esc(i.alert.rule)}</span>
      <span class="meta"><span class="sev ${i.alert.severity}">${i.alert.severity}</span>${i.id} ${tag}</span></li>`;
  }).join("");
  document.querySelectorAll("#queue li").forEach((li) => (li.onclick = () => open(li.dataset.id)));
}

function chips(ids) {
  return `<span class="chips">${(ids || []).map((id) => `<span class="chip" data-ev="${esc(id)}">${esc(id)}</span>`).join("")}</span>`;
}

async function showEvidence(id) {
  let body;
  if (id.startsWith("EVT-")) body = await api(`/api/incidents/${state.current}/events/${id}`).catch((e) => ({ error: e.message }));
  else if (/^T\d{4}/.test(id)) body = { technique: id, link: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/` };
  else body = { note: "Threat-intel or inventory record returned by a lookup tool during the investigation.", id };
  $("#evidence-title").textContent = id;
  $("#evidence-body").textContent = JSON.stringify(body, null, 2);
  $("#evidence").showModal();
}

function reportHtml(run) {
  const r = run.report;
  const u = run.usage || {};
  const stats = `<div class="stats">
      <span>Status <b>${run.status}</b></span><span>Tokens <b>${(u.total_tokens || 0).toLocaleString()}</b></span>
      <span>Model calls <b>${u.model_calls || 0}</b></span><span>Tool calls <b>${(run.steps || []).length}</b></span>
      <span>Duration <b>${run.duration_s ?? "–"}s</b></span><span>Model <b>${esc(run.model)}</b></span></div>`;
  if (!r) return `<section class="card"><h2>Investigation</h2>${stats}${run.error ? `<p class="err">${esc(run.error)}</p>` : ""}</section>`;
  return `
  <section class="card">
    <div class="head"><h2>Report</h2><div><span class="verdict ${r.verdict}">${VERDICT[r.verdict]}</span> <span class="sev ${r.severity}">${r.severity}</span> <span class="muted">confidence ${r.confidence}</span></div></div>
    <p class="summary">${esc(r.summary)}</p>${stats}
    <h3>Findings</h3><ul class="list">${r.findings.map((f) => `<li>${esc(f.statement)} ${chips(f.evidence_ids)}</li>`).join("")}</ul>
    ${r.timeline.length ? `<h3>Timeline</h3><ul class="list timeline">${r.timeline.map((t) => `<li><time>${esc(t.time)}</time><span>${esc(t.description)} ${chips(t.evidence_ids)}</span></li>`).join("")}</ul>` : ""}
    ${r.techniques.length ? `<h3>MITRE ATT&amp;CK</h3><ul class="list tech">${r.techniques.map((t) => `<li><a href="https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/" target="_blank" rel="noopener">${esc(t.id)}</a> ${esc(t.name)} · <span class="muted">${esc(t.rationale)}</span> ${chips(t.evidence_ids)}</li>`).join("")}</ul>` : ""}
    ${r.next_steps.length ? `<h3>Next steps</h3><ul class="list">${r.next_steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : ""}
  </section>`;
}

function actionsHtml(run) {
  if (!run.proposals || !run.proposals.length) return `<section class="card"><h2>Proposed actions</h2><p class="muted">The agent proposed no actions.</p></section>`;
  return `<section class="card"><h2>Proposed actions <span class="muted">· nothing runs until a person approves it</span></h2>
    <ul class="list">${run.proposals.map((a) => `<li class="action" data-act="${a.id}">
      <span class="what">${a.id} · ${a.type.replace(/_/g, " ")} <code>${esc(a.target)}</code></span>
      ${a.status === "pending"
        ? `<span class="btns"><button class="approve">Approve</button><button class="reject">Reject</button></span>`
        : `<span class="status-pill ${a.status}">${a.status} by ${esc(a.decided_by)}</span>`}
      <span class="why">${esc(a.justification)} ${chips(a.evidence_ids)}</span>
      ${a.result ? `<span class="result">${esc(a.result)}</span>` : ""}
    </li>`).join("")}</ul></section>`;
}

function traceHtml(spans, run) {
  if (!spans.length) return "";
  const rows = spans.filter((s) => s.name !== "investigation").sort((a, b) => a.start - b.start);
  const t0 = rows[0]?.start || 0;
  const steps = run.steps || [];
  let toolIdx = 0;
  return `<section class="card"><details><summary>Trace · ${rows.length} spans</summary>
    <table class="trace"><thead><tr><th>+s</th><th>Span</th><th>ms</th><th>Tokens in / out</th><th>Tool calls</th><th>Detail</th></tr></thead><tbody>
    ${rows.map((s) => {
      const a = s.attributes;
      let detail = "";
      if (s.name === "tool.call") {
        const st = steps[toolIdx++];
        detail = st ? esc(JSON.stringify(st.input)) : "";
      } else detail = `stop=${esc(a.stop_reason)} model=${esc(a.model)}`;
      return `<tr><td>${(s.start - t0).toFixed(1)}</td><td>${s.name === "tool.call" ? esc(a.tool) : "model call"}${a.is_error ? ' <span class="err">error</span>' : ""}</td>
        <td>${s.duration_ms}</td><td>${a.input_tokens != null ? `${a.input_tokens} / ${a.output_tokens}` : ""}</td>
        <td>${a.tool_calls ?? ""}</td><td class="code" title="${detail}">${detail}</td></tr>`;
    }).join("")}
    </tbody></table></details></section>`;
}

async function open(id) {
  state.current = id;
  clearInterval(state.poll);
  document.querySelectorAll("#queue li").forEach((li) => li.classList.toggle("active", li.dataset.id === id));
  const inc = await api(`/api/incidents/${id}`);
  const runId = inc.runs[0];
  const run = runId ? await api(`/api/runs/${runId}`) : null;
  const spans = runId ? await api(`/api/runs/${runId}/trace`) : [];
  const a = inc.alert;
  const running = state.incidents.find((i) => i.id === id)?.running;
  $("#detail").innerHTML = `
    <section class="card">
      <div class="head"><div><h1>${esc(inc.title)}</h1><span class="muted">${inc.id} · ${esc(a.rule)} · ${inc.event_count} log events available</span></div>
      <button class="primary" id="go" ${!state.live || running ? "disabled" : ""}>${running ? "Investigating…" : run ? "Re-investigate" : "Investigate"}</button></div>
      <p>${esc(a.summary)}</p>
      <dl class="kv">${Object.entries(a.entities).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? v.join(", ") : v)}</dd>`).join("")}
      <dt>triggered by</dt><dd>${chips(a.triggering_event_ids)}</dd><dt>alert severity</dt><dd><span class="sev ${a.severity}">${a.severity}</span></dd></dl>
      ${!state.live ? `<p class="notice">The model isn't reachable (is Ollama running?), so new investigations are disabled. Recorded runs are shown below.</p>` : ""}
    </section>
    ${run ? (run.status === "running" ? `<section class="card"><h2>Investigating…</h2><p class="muted">Tool calls appear in the trace as they happen.</p></section>` : reportHtml(run) + actionsHtml(run)) : ""}
    ${run ? traceHtml(spans, run) : ""}`;

  const go = $("#go");
  if (go) go.onclick = async () => {
    go.disabled = true;
    go.textContent = "Investigating…";
    try {
      await api(`/api/incidents/${id}/investigate`, { method: "POST" });
      await loadQueue();
      state.poll = setInterval(async () => {
        await loadQueue();
        if (!state.incidents.find((i) => i.id === id)?.running) { clearInterval(state.poll); open(id); }
      }, 3000);
    } catch (e) { alert(e.message); go.disabled = false; }
  };
  document.querySelectorAll("[data-ev]").forEach((c) => (c.onclick = () => showEvidence(c.dataset.ev)));
  document.querySelectorAll("[data-act]").forEach((li) => {
    li.querySelectorAll("button").forEach((b) => (b.onclick = async () => {
      const approver = approverInput.value.trim();
      if (!approver) { approverInput.focus(); alert("Enter your name in 'Approving as' first: every decision is audited."); return; }
      const decision = b.classList.contains("approve") ? "approve" : "reject";
      const note = decision === "reject" ? prompt("Reason for rejecting (optional)") || "" : "";
      try {
        await api(`/api/runs/${run.run_id}/actions/${li.dataset.act}`, { method: "POST", body: JSON.stringify({ decision, approver, note }) });
        await loadQueue();
        open(id);
      } catch (e) { alert(e.message); }
    }));
  });
}

loadHealth().then(loadQueue).then(() => state.incidents[0] && open(state.incidents[0].id));
