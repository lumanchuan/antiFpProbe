const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const staging = process.argv[2];
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(staging ? path.join(staging, 'p0f.html') : path.join(root, 'templates/p0f.html'), 'utf8');
const script = fs.readFileSync(staging ? path.join(staging, 'p0f.js') : path.join(root, 'static/js/p0f.js'), 'utf8');
assert.ok(html.includes('受保护资产标签'));
assert.ok(html.includes('实机核验：{{ deployment.verified_kernel }}'));
assert.ok(!html.includes('最近识别系统'));
const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [id, {
  textContent: '', innerHTML: '', value: '', classList: {toggle() {}, add() {}},
  addEventListener() {}, getBoundingClientRect() { return {width: 0, height: 0}; }
}]));
elements.get('asset-os').textContent = 'Linux 2.6';
elements.get('asset-kernel').textContent = '实机核验：Linux 5.4.0-150-generic';
elements.get('profile-family').value = 'all';
const context = vm.createContext({
  console, setInterval() {}, clearTimeout() {}, setTimeout() {}, requestAnimationFrame() {},
  fetch: () => new Promise(() => {}),
  window: {addEventListener() {}},
  document: {
    getElementById(id) { assert.ok(elements.has(id), `Missing HTML element: ${id}`); return elements.get(id); },
    querySelectorAll() { return []; },
    body: {classList: {toggle() {}}}
  }
});
vm.runInContext(script, context);
const initial = {
  runtime: {telemetry: {}, processes: [], busy: false, stage: 'idle'},
  statistics: {sensor: {}, counts: {SYN: 0, 'SYN-ACK': 0}, events: [], os_distribution: [], chart: {}},
  selected: {id: 'mac', name: 'Mac OS X:10.x'}
};
for (const os of ['Mac OS X 10.x', 'Windows 7 or 8']) {
  initial.statistics.events = [{side: 'SYN', os, time: 1789300833, params: 'none', mode: 'p0f'}];
  vm.runInContext(`state=${JSON.stringify(initial)}; render(); render();`, context);
  assert.equal(elements.get('asset-os').textContent, 'Linux 2.6');
  assert.equal(elements.get('asset-kernel').textContent, '实机核验：Linux 5.4.0-150-generic');
  assert.equal(elements.get('target-os').textContent, 'Mac OS X:10.x');
  assert.ok(elements.get('recent-table').innerHTML.includes(os));
}
const profiles = [
  {id: 'mac', name: 'Mac OS X', supported: true, options: ['ts']},
  {id: 'blocked', name: 'Blocked candidate', supported: false, options: [], reason: 'internal diagnostic'},
  {id: 'unknown', name: 'Unknown candidate', options: []}
];
vm.runInContext(`profiles=${JSON.stringify(profiles)}; renderProfiles();`, context);
assert.equal(elements.get('profile-count').textContent, '1 个指纹');
assert.ok(elements.get('profile-grid').innerHTML.includes('Mac OS X'));
assert.ok(!elements.get('profile-grid').innerHTML.includes('Blocked candidate'));
assert.ok(!elements.get('profile-grid').innerHTML.includes('internal diagnostic'));
assert.ok(!elements.get('profile-grid').innerHTML.includes('Unknown candidate'));
elements.get('profile-search').value = 'blocked';
vm.runInContext('renderProfiles();', context);
assert.ok(elements.get('profile-grid').innerHTML.includes('没有匹配的指纹'));
elements.get('profile-search').value = '';
vm.runInContext('state.runtime.busy=true; renderProfiles();', context);
assert.match(elements.get('profile-grid').innerHTML, /data-profile="mac" disabled/);
profiles[0] = {...profiles[0], candidate: true, family: 'Mac', variant: '库条目 #51'};
profiles.push({id: 'bsd', name: 'FreeBSD:8.x', supported: true, family: 'FreeBSD', candidate: true, options: ['ts']});
vm.runInContext(`state.runtime.busy=false; profiles=${JSON.stringify(profiles)}; renderProfiles();`, context);
assert.equal(elements.get('profile-count').textContent, '2 个指纹');
assert.ok(elements.get('profile-grid').innerHTML.includes('库条目 #51'));
  assert.ok(!elements.get('profile-grid').innerHTML.includes('badge warning'));
elements.get('profile-family').value = 'FreeBSD';
vm.runInContext('renderProfiles();', context);
assert.ok(elements.get('profile-grid').innerHTML.includes('FreeBSD:8.x'));
assert.ok(!elements.get('profile-grid').innerHTML.includes('Mac OS X'));
console.log('PASS: asset label survives polling; observation history retained; unavailable cards excluded; switching controls preserved.');
