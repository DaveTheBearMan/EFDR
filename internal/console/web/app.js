'use strict';
// Everything an agent sends is put in the page with textContent: it is text.

const $ = (id) => document.getElementById(id);
const LABEL = {approve: 'Approve', kill: 'Kill now', ignore: 'Ignore', remove: 'Remove', keep: 'Keep', undo: 'Restore'};
const DANGER = new Set(['kill', 'remove']);
let view = null, creds = null, tab = 'alerts', timer = null;

function h(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function say(text) { $('msg').textContent = text || ''; }

async function api(method, path, body) {
  const opt = {method, credentials: 'same-origin', headers: {}};
  if (method !== 'GET') opt.headers['X-XDR'] = '1';
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401) { showLogin(); throw new Error('log in'); }
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r.status === 204 ? null : r.json();
}

function ago(iso) {
  if (!iso || iso.startsWith('0001')) return 'never';
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 90) return s + 's ago';
  if (s < 5400) return Math.round(s / 60) + 'm ago';
  return Math.round(s / 3600) + 'h ago';
}
function clock(iso) { return iso ? iso.slice(11, 19) : ''; }
function sevClass(s) { return s === 'critical' || s === 'high' ? 'crit' : s === 'medium' ? 'warn' : 'info'; }
function pill(text, c) { return h('span', 'pill p-' + c, text); }

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
  } catch (e) { /* fall through to the old way */ }
  const t = document.createElement('textarea');
  t.value = text; t.readOnly = true; t.className = 'offscreen';
  document.body.appendChild(t); t.focus(); t.select(); t.setSelectionRange(0, text.length);
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  document.body.removeChild(t);
  return ok;
}

function stat(k, v, cls) {
  const s = h('div', 'stat' + (cls ? ' ' + cls : ''));
  s.append(h('span', 'k', k), h('span', 'v', String(v)));
  return s;
}

function renderHeader() {
  const s = view.Summary;
  $('clock').textContent = 'jump box · ' + clock(view.Now) + ' UTC · rules ' + view.Rules;
  const strip = $('strip');
  clear(strip);
  strip.append(stat('Need you', s.Need, s.Need ? 'crit' : ''), stat('Auto-killed', s.Killed), stat('Agents up', s.AgentsUp + '/' + s.AgentsTotal, s.AgentsUp < s.AgentsTotal ? 'warn' : ''), stat('Blocked endpoints', s.Blocks, s.Blocks ? 'warn' : ''));
  const open = view.Approvals.filter((a) => !a.Actions.includes('undo')).length;
  $('n-approvals').textContent = open ? String(open) : '';
  const pend = view.Approvals.filter((a) => a.Kind === 'session').length;
  $('n-sessions').textContent = pend ? String(pend) : '';
}

function renderAlerts() {
  const p = $('p-alerts');
  clear(p);
  if (!view.Alerts.length) p.append(h('p', 'why', 'Nothing yet.'));
  for (const a of view.Alerts) {
    const c = sevClass(a.Severity);
    const card = h('article', 'item ' + c);
    const row = h('div', 'row');
    row.append(pill(a.Kind.replace(/-/g, ' ') + ' · ' + a.Action, c), h('span', 'host', a.Host), h('span', 'when', clock(a.Time)));
    card.append(row, h('div', 'title', a.Detail || a.Kind));
    const lines = [];
    if (a.Chain && a.Chain.length) lines.push(a.Chain.join(' → '));
    if (a.Remote) lines.push('remote ' + a.Remote);
    if (a.Exe) lines.push('exe ' + a.Exe);
    if (a.Path) lines.push('path ' + a.Path);
    if (a.SHA256) lines.push('sha256 ' + a.SHA256);
    if (lines.length) card.append(h('div', 'chain', lines.join('\n')));
    if (a.Steps && a.Steps.length) {
      const steps = h('div', 'steps');
      for (const s of a.Steps) steps.append(h('span', '', s));
      card.append(steps);
    }
    p.append(card);
  }
}

function approvalCard(a) {
  const card = h('article', 'item ' + (a.Kind === 'proc' ? 'crit' : a.Kind === 'session' ? 'warn' : 'info'));
  const row = h('div', 'row');
  row.append(pill(a.Kind, a.Kind === 'proc' ? 'crit' : 'warn'), h('span', 'host', a.Host));
  if (a.Deadline && !a.Deadline.startsWith('0001')) {
    const left = h('span', 'when');
    left.deadline = Date.parse(a.Deadline);
    left.className = 'when countdown';
    row.append(left);
  } else row.append(h('span', 'when', clock(a.Time)));
  const msg = h('div', 'why');
  const btns = h('div', 'btns');
  for (const act of a.Actions) {
    const b = h('button', 'btn' + (act === a.Actions[0] && !DANGER.has(act) ? ' primary' : DANGER.has(act) ? ' danger' : ''), LABEL[act] || act);
    b.type = 'button';
    b.addEventListener('click', async () => {
      if (DANGER.has(act) && !window.confirm((LABEL[act] || act) + ': ' + a.Title + ' on ' + a.Host + '?')) return;
      btns.querySelectorAll('button').forEach((x) => { x.disabled = true; });
      try { await api('POST', '/api/decide', {id: a.ID, action: act}); say(''); await refresh(); }
      catch (e) { msg.textContent = e.message; btns.querySelectorAll('button').forEach((x) => { x.disabled = false; }); }
    });
    btns.append(b);
  }
  card.append(row, h('div', 'title', a.Title), h('div', 'why', a.Why), msg, btns);
  return card;
}

function renderApprovals() {
  const p = $('p-approvals');
  clear(p);
  if (!view.Approvals.length) p.append(h('p', 'why', 'Nothing needs you.'));
  for (const a of view.Approvals) p.append(approvalCard(a));
}

function renderSessions() {
  const p = $('p-sessions');
  clear(p);
  for (const a of view.Approvals) if (a.Kind === 'session') p.append(approvalCard(a));
  const body = h('tbody');
  for (const s of view.Sessions) {
    const tr = h('tr');
    const st = s.Status === 'pending' ? 'warn' : s.Status === 'ended' ? 'crit' : 'ok';
    const status = h('td'); status.append(pill(s.Status, st));
    tr.append(h('td', 'm', s.Host), h('td', '', s.User), h('td', 'm', s.From), h('td', 'm', clock(s.Time)), status);
    body.append(tr);
  }
  const t = h('table'), head = h('thead'), hr = h('tr');
  for (const c of ['Host', 'User', 'From', 'Seen', 'Status']) hr.append(h('th', '', c));
  head.append(hr); t.append(head, body);
  const wrap = h('div', 'tbl'); wrap.append(t);
  p.append(wrap);
}

// killWord is how the page names an agent's kill switch.
function killWord(k) { return k === 'on' ? 'on' : k === 'off' ? 'off' : 'from config'; }

// setKill turns kill on or off for host, or for every host with '*', after
// the operator says yes.
async function setKill(host, kill, msg) {
  const who = host === '*' ? 'every enabled host' : host;
  const what = kill
    ? 'Turn kill ON for ' + who + '? Its agent will kill what it decides to kill. Scored services, gray accounts and a pause stay protected.'
    : 'Turn kill OFF for ' + who + '? Its agent will only report what it would have killed.';
  if (!window.confirm(what)) return;
  try { await api('POST', '/api/mode', {host, kill}); say(''); await refresh(); }
  catch (e) { if (msg) msg.textContent = e.message; else say(e.message); }
}

function killButton(host, kill, label, cls) {
  const b = h('button', 'btn' + (cls ? ' ' + cls : ''), label); b.type = 'button';
  b.addEventListener('click', () => setKill(host, kill));
  return b;
}

function renderKillAll() {
  const p = $('p-killall');
  clear(p);
  const ks = view.Hosts.map((x) => killWord(x.Kill));
  const now = !ks.length ? 'no hosts' : ks.every((k) => k === ks[0]) ? ks[0] : 'mixed';
  const card = h('article', 'item info');
  const row = h('div', 'row');
  row.append(pill('kill, all hosts', 'warn'), h('span', 'host', now));
  const btns = h('div', 'btns');
  btns.append(killButton('*', true, 'Turn on for all', 'danger'), killButton('*', false, 'Turn off for all'));
  card.append(row, h('div', 'why', 'Whether agents kill what they detect. Off: they only report it ("would-kill"). A disabled host is left out.'), btns);
  p.append(card);
}

function renderHosts() {
  renderKillAll();
  const p = $('p-hosts');
  clear(p);
  const body = h('tbody');
  for (const x of view.Hosts) {
    const tr = h('tr');
    const name = h('td', 'm'), dot = h('span', 'dot d-' + (x.Status === 'up' ? 'ok' : x.Status === 'never' ? 'warn' : 'crit'));
    name.append(dot, document.createTextNode(x.Name));
    const state = h('td'); state.append(pill(x.Status, x.Status === 'up' ? 'ok' : 'crit'));
    const k = killWord(x.Kill);
    const kill = h('td', 'kill'); const kb = h('div', 'btns');
    kb.append(pill(k, k === 'on' ? 'ok' : k === 'off' ? 'warn' : 'info'));
    if (k !== 'on') kb.append(killButton(x.Name, true, 'Turn on', 'danger'));
    if (k !== 'off') kb.append(killButton(x.Name, false, 'Turn off'));
    kill.append(kb);
    const act = h('td'); const b = h('button', 'btn danger', 'Break-glass…'); b.type = 'button';
    b.addEventListener('click', () => breakglass(x.Name));
    act.append(b);
    tr.append(name, state, kill, h('td', 'm', ago(x.Last)), h('td', 'm', String(x.Drift)), h('td', 'm', String(x.Alerts)), act);
    body.append(tr);
  }
  const t = h('table'), head = h('thead'), hr = h('tr');
  for (const c of ['Host', 'Agent', 'Kill', 'Last beat', 'Drift', 'Alerts (1h)', '']) hr.append(h('th', '', c));
  head.append(hr); t.append(head, body);
  const wrap = h('div', 'tbl'); wrap.append(t);
  p.append(wrap, h('div', 'why', 'Kill "from config" is the kill of the host\'s agent.json until you turn it on or off here. Break-glass mints a token for one host that you can paste into `xdr breakglass` on it.'), h('div', '', ''));
  p.lastChild.id = 'bgOut';
}

async function breakglass(host) {
  const action = window.prompt('Token for ' + host + ': pause, approve-session or uninstall?', 'pause');
  if (!action) return;
  const minutes = parseInt(window.prompt('Valid for how many minutes (5 to 1440)?', '120'), 10);
  if (!minutes) return;
  try {
    const r = await api('POST', '/api/breakglass', {host, action, minutes});
    const out = $('bgOut'); clear(out);
    const input = h('input', 'token'); input.readOnly = true; input.value = r.token;
    const b = h('button', 'btn primary', 'Copy token'); b.type = 'button';
    b.addEventListener('click', async () => { b.textContent = (await copyText(r.token)) ? 'Copied' : 'Select and copy'; input.select(); });
    out.append(h('p', 'why', action + ' token for ' + host + ', ' + minutes + ' min:'), input, b);
  } catch (e) { say(e.message); }
}

function renderCreds() {
  const p = $('p-creds');
  clear(p);
  if (!creds) { p.append(h('p', 'why', 'Loading…')); return; }
  const top = h('div', 'btns');
  const all = h('button', 'btn primary', 'Copy all'); all.type = 'button';
  all.addEventListener('click', async () => { all.textContent = (await copyText(creds.block)) ? 'Copied' : 'Copy failed'; });
  top.append(all);
  p.append(top);
  if (!creds.entries.length) p.append(h('p', 'why', 'Nothing rotated yet.'));
  const body = h('tbody');
  for (const e of creds.entries) {
    const tr = h('tr');
    const pw = h('td', 'm secret', '••••••••••••••••••••');
    let shown = false;
    const reveal = h('button', 'btn', 'Reveal'); reveal.type = 'button';
    reveal.addEventListener('click', () => { shown = !shown; pw.textContent = shown ? e.Password : '••••••••••••••••••••'; reveal.textContent = shown ? 'Hide' : 'Reveal'; });
    const copy = h('button', 'btn', 'Copy'); copy.type = 'button';
    copy.addEventListener('click', async () => { copy.textContent = (await copyText(e.Password)) ? 'Copied' : 'Failed'; });
    const rot = h('button', 'btn danger', 'Rotate again'); rot.type = 'button';
    rot.addEventListener('click', async () => {
      if (!window.confirm('Rotate ' + e.Account + ' on ' + e.Host + '? Check the scoring engine first.')) return;
      try { creds = await api('POST', '/api/rotate', {host: e.Host, users: [e.Account], samba: e.Service === 'samba' ? [e.Account] : []}).then(loadCreds); render(); }
      catch (err) { say(err.message); }
    });
    const act = h('td'); const box = h('div', 'btns'); box.append(reveal, copy, rot); act.append(box);
    tr.append(h('td', 'm', e.Host), h('td', '', e.Service), h('td', '', e.Account), pw, h('td', 'm', ago(e.Rotated)), act);
    body.append(tr);
  }
  const t = h('table'), head = h('thead'), hr = h('tr');
  for (const c of ['Host', 'Service', 'Account', 'Password', 'Rotated', '']) hr.append(h('th', '', c));
  head.append(hr); t.append(head, body);
  const wrap = h('div', 'tbl'); wrap.append(t);
  p.append(wrap);
}
const loadCreds = () => api('GET', '/api/creds');

function render() {
  if (!view) return;
  renderHeader();
  ({alerts: renderAlerts, approvals: renderApprovals, sessions: renderSessions, hosts: renderHosts, creds: renderCreds})[tab]();
  tick();
}

function tick() {
  for (const e of document.querySelectorAll('.countdown')) {
    const s = Math.round((e.deadline - Date.now()) / 1000);
    e.textContent = s <= 0 ? 'ended' : s >= 3600 ? Math.floor(s / 3600) + 'h ' + Math.floor(s % 3600 / 60) + 'm left' : Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0') + ' left';
  }
}

async function refresh() {
  try {
    view = await api('GET', '/api/state');
    if (tab === 'creds') creds = await loadCreds();
    $('login').hidden = true; $('app').hidden = false;
    say('');
    render();
  } catch (e) { if (e.message !== 'log in') say('Cannot reach the controller: ' + e.message); }
}

function showLogin() {
  $('app').hidden = true; $('login').hidden = false;
  view = null; creds = null;
  $('password').focus();
}

document.querySelectorAll('#tabs button').forEach((b) => b.addEventListener('click', async () => {
  tab = b.dataset.tab;
  document.querySelectorAll('#tabs button').forEach((x) => x.setAttribute('aria-selected', String(x === b)));
  document.querySelectorAll('[data-panel]').forEach((p) => { p.hidden = p.dataset.panel !== tab; });
  if (tab === 'creds') { try { creds = await loadCreds(); } catch (e) { say(e.message); } }
  render();
}));

$('loginForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const r = await fetch('/login', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({password: $('password').value})});
  $('password').value = '';
  if (r.status === 204) { $('loginMsg').textContent = ''; await refresh(); }
  else $('loginMsg').textContent = r.status === 429 ? 'Too many attempts; wait a minute.' : 'No.';
});
$('logout').addEventListener('click', async () => { await fetch('/logout', {method: 'POST', credentials: 'same-origin', headers: {'X-XDR': '1'}}); showLogin(); });

setInterval(() => { if (!document.hidden && view) refresh(); }, 2000);
setInterval(tick, 1000);
refresh();
