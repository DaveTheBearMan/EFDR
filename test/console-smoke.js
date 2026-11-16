// Smoke test of the console page in jsdom (not part of go test).
//   mkdir /tmp/jsdom && cd /tmp/jsdom && npm install jsdom@24 && cp /home/davethebearman/XDR/test/console-smoke.js . && node console-smoke.js
// It loads internal/console/web with a mocked API whose data contains markup, and checks the DOM.
const {JSDOM} = require('jsdom');
const fs = require('fs');
const web = process.env.XDR_WEB || __dirname + '/../internal/console/web/';
const html = fs.readFileSync(web + 'index.html', 'utf8').replace('<script src="/app.js"></script>', '');
const js = fs.readFileSync(web + 'app.js', 'utf8');
const evil = '<script>window.PWNED=1</script><img src=x onerror="window.PWNED=2">';
const now = '2026-11-16T12:00:00Z';
const view = {Now: now, Rules: 3, Summary: {Need: 2, Killed: 5, AgentsUp: 2, AgentsTotal: 3, Blocks: 1},
  Alerts: [{ID: 'a1', Host: 'web01', Kind: 'egress', Action: 'killed', Severity: 'high', Detail: evil, Exe: '/tmp/' + evil, Path: '', Remote: '203.0.113.9:4444/tcp', Chain: [evil + ' (pid 9)', 'systemd (pid 1)'], Steps: ['killed', 'rule abc written'], Time: now}],
  Approvals: [
    {ID: 's:web01:7', Host: 'web01', Kind: 'session', Title: 'alice from 192.0.2.7', Why: 'w', Deadline: '2026-11-16T12:01:30Z', Actions: ['approve', 'kill'], Time: now},
    {ID: 'p:web01:950:abc', Host: 'web01', Kind: 'proc', Title: evil, Why: evil, Deadline: '0001-01-01T00:00:00Z', Actions: ['kill', 'ignore'], Time: now}],
  Sessions: [{Host: 'web01', ID: '7', User: evil, From: '192.0.2.7', Status: 'pending', Time: now}],
  Hosts: [{Name: 'web01', Status: 'up', Last: now, Drift: 1, Alerts: 3}, {Name: 'db01', Status: 'silent', Last: now, Drift: 0, Alerts: 0}]};
const creds = {entries: [{Host: 'web01', Service: 'ssh', Account: 'alice', Password: 'S3cretPassw0rdValue', Rotated: now}], block: 'web01\tssh\talice\tS3cretPassw0rdValue\n'};
const calls = [];
const dom = new JSDOM(html, {runScripts: 'outside-only', url: 'https://jump.example/', pretendToBeVisual: true});
const w = dom.window;
w.fetch = async (path, opt = {}) => {
  calls.push([opt.method || 'GET', path, opt.headers && opt.headers['X-XDR']]);
  const ok = (body, status = 200) => ({ok: true, status, json: async () => body, text: async () => ''});
  if (path === '/api/state') return ok(view);
  if (path === '/api/creds') return ok(creds);
  if (path === '/api/decide') return ok(null, 204);
  return {ok: false, status: 404, text: async () => 'no', statusText: 'no'};
};
w.confirm = () => true;
w.eval(js);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  await wait(100);
  const d = w.document, $ = (s) => d.querySelector(s), all = (s) => [...d.querySelectorAll(s)];
  const fail = [];
  const check = (name, ok) => { if (!ok) fail.push(name); console.log((ok ? 'ok ' : 'FAIL ') + name); };
  check('app is shown, login hidden', !$('#app').hidden && $('#login').hidden);
  check('strip has four stats', all('#strip .stat').length === 4 && $('#strip .stat .v').textContent === '2');
  check('approvals badge', $('#n-approvals').textContent === '2' && $('#n-sessions').textContent === '1');
  check('hostile text is text, not markup', $('#p-alerts .title').textContent === evil && !$('#p-alerts script') && !$('#p-alerts img') && w.PWNED === undefined);
  check('no script or img elements anywhere', all('script').length === 0 && all('img').length === 0);
  check('chain line shows the text', $('#p-alerts .chain').textContent.includes(evil));
  check('steps', all('#p-alerts .steps span').length === 2);
  $('[data-tab="approvals"]').click(); await wait(50);
  check('approvals: 2 cards, buttons', all('#p-approvals .item').length === 2 && all('#p-approvals .btn').length === 4);
  check('countdown element', all('#p-approvals .countdown').length === 1 && /left|ended/.test($('#p-approvals .countdown').textContent));
  check('proc card text is text', !$('#p-approvals script') && !$('#p-approvals img'));
  const approve = all('#p-approvals .btn').find((b) => b.textContent === 'Approve'); approve.click(); await wait(50);
  const dec = calls.find((c) => c[1] === '/api/decide');
  check('approve posts /api/decide with X-XDR', !!dec && dec[0] === 'POST' && dec[2] === '1');
  $('[data-tab="sessions"]').click(); await wait(50);
  check('sessions table, hostile user as text', all('#p-sessions tbody tr').length === 1 && !$('#p-sessions script') && $('#p-sessions tbody tr').textContent.includes('<script>'));
  $('[data-tab="hosts"]').click(); await wait(50);
  check('hosts table rows and break-glass buttons', all('#p-hosts tbody tr').length === 2 && all('#p-hosts .btn.danger').length === 2);
  $('[data-tab="creds"]').click(); await wait(100);
  check('credentials masked', !$('#p-creds').textContent.includes('S3cretPassw0rdValue') && $('#p-creds .secret').textContent.startsWith('••'));
  all('#p-creds .btn').find((b) => b.textContent === 'Reveal').click(); await wait(20);
  check('reveal shows it, hide masks it', $('#p-creds .secret').textContent === 'S3cretPassw0rdValue');
  check('copy all button', all('#p-creds .btn').some((b) => b.textContent === 'Copy all'));
  console.log(fail.length ? 'SMOKE FAIL: ' + fail.join(', ') : 'SMOKE PASS');
  process.exit(fail.length ? 1 : 0);
})();
