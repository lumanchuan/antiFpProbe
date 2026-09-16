'use strict';
const $ = id => document.getElementById(id);
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number = value => Number(value || 0).toLocaleString('zh-CN');
const timeText = seconds => new Date(seconds * 1000).toLocaleTimeString('zh-CN', {hour12:false, timeZone:'Asia/Shanghai'});
const names = ['SEQ','ECN','T2','T3','T4','T5','T6','T7','IE1','IE2','U1'];
let state = null, csrf = '', profileList = [], view = 'overview', recordView = 'events', logView = 'data', polling = false, modalBusy = false;
let toastTimer, connectionOK = false;
function icons() { if (window.lucide) lucide.createIcons(); }
function setText(id, value) { $(id).textContent = value; }
function toast(message, error=false) { clearTimeout(toastTimer); $('toast').className='toast'+(error?' error':''); setText('toast',message); toastTimer=setTimeout(()=>$('toast').classList.add('hidden'),6000); }
async function api(path, options={}) {
  const headers = {'Content-Type':'application/json', ...options.headers};
  if (options.method && options.method !== 'GET') headers['X-CSRF-Token']=csrf;
  const response = await fetch(path,{...options,headers,cache:'no-store'});
  const data = await response.json();
  if (!response.ok) {
    if(response.status===401 && path!=='/api/login') { csrf=''; showLogin(); }
    throw new Error(data.error || `请求失败 (${response.status})`);
  }
  return data;
}
function showLogin() { if(!$('login-dialog').open) $('login-dialog').showModal(); }
function openView(next) {
  view=next;
  document.querySelectorAll('.view').forEach(el=>el.classList.toggle('hidden',el.id!==`view-${next}`));
  document.querySelectorAll('[data-view]').forEach(el=>el.classList.toggle('active',el.dataset.view===next));
  setText('view-title', {overview:'运行总览',events:'探针记录',profiles:'指纹库',logs:'运行日志'}[next]);
  if(next==='profiles') loadProfiles();
  if(next==='events') renderRecords();
  if(next==='logs') loadLog();
  if(next==='overview') drawTrend();
}
function mode() { return document.querySelector('input[name="mode"]:checked').value; }
function render() {
  if(!state) return;
  const rt=state.runtime, data=rt.telemetry, stats=state.statistics;
  const dataProcess=rt.processes.find(p=>p.plane==='data');
  const controlProcess=rt.processes.find(p=>p.plane==='control');
  const hardwareReady=Boolean(data.fresh && data.ready && dataProcess && dataProcess.program===data.program && ['scan_monitor','antiFpProbe'].includes(data.program));
  const running=hardwareReady && rt.link_ready && !rt.busy;
  const protecting=running && data.program==='antiFpProbe';
  setText('metric-scans',number(stats.scan_sessions));
  setText('metric-probes',number(stats.total));
  setText('metric-sources',running && !protecting ? number(stats.active_sources) : '—');
  setText('metric-confidence',`${number(stats.high_confidence)} 个高置信会话 · 估算值`);
  setText('metric-mode',rt.busy?'切换中':dataProcess?.program==='p0f'?'p0f 已占用':hardwareReady && !rt.link_ready?'链路未就绪':protecting?'抗测绘':running?'监测转发':dataProcess?'仅数据面':'未启动');
  setText('metric-mode-detail',dataProcess?dataProcess.program:'数据面与控制面未运行');
  setText('topology-program',dataProcess?dataProcess.program:'NO PIPELINE');
  $('scene').classList.toggle('scene-running',running);
  $('telemetry-badge').className='badge'+(running?'':rt.busy?' warning':' muted');
  setText('telemetry-badge',running?'硬件遥测在线':hardwareReady?'等待链路':rt.busy?'切换中断':'监测暂停');
  setText('coverage',running?(protecting?'抗测绘 · TCP 计数可用 / 来源与 IE、U1 明细不可用':'监测转发 · 入口 60 → 192.168.3.2'):'无实时监测 · 保留历史统计');
  setText('telemetry-time',data.time?timeText(data.time):'--');
  for(const p of [52,60]) {
    const port=(data.ports||[]).find(x=>x.port===p);
    setText(`port${p}`,`DEV ${p} · ${hardwareReady && port?(port.enabled && port.up?'LINK UP':'LINK DOWN'):'未读取'}`);
  }
  setText('target-os',state.selected.name);
  setText('profile-status',protecting && data.active?.sha===state.selected.id?'已下发 · '+data.active.os:protecting?'等待新指纹下发':'已选定 · 待抗测绘模式生效');
  setText('operation-status',rt.busy?'执行中':rt.stage==='error'?'异常':running?'运行中':hardwareReady?'链路未就绪':'待命');
  $('operation-status').className='badge'+(rt.stage==='error'?' danger':rt.busy || hardwareReady && !rt.link_ready?' warning':running?'':' muted');
  $('operation-message').className='operation-message'+(rt.stage==='error'?' error':'');
  setText('operation-message',!rt.busy && rt.stage!=='error' && hardwareReady && !rt.link_ready
    ? `链路未就绪：DEV ${(rt.pending_ports||[]).join(' / ')}，请等待或检查网卡连接` : rt.message);
  setText('data-pid',dataProcess?`${dataProcess.program} · PID ${dataProcess.pid}`:'无运行进程');
  setText('control-pid',controlProcess?`${controlProcess.program} · PID ${controlProcess.pid}`:'无运行进程');
  $('step-data').className=dataProcess?'done':rt.busy?'loading':'';
  $('step-ready').className=hardwareReady || ['control','links'].includes(rt.stage)?'done':rt.busy && rt.stage==='data'?'loading':'';
  $('step-control').className=running?'done':rt.busy && ['control','links'].includes(rt.stage)?'loading':'';
  $('start').disabled=rt.busy || modalBusy;
  $('stop').disabled=rt.busy || modalBusy || !rt.processes.length;
  document.querySelectorAll('input[name="mode"]').forEach(el=>el.disabled=rt.busy);
  document.body.classList.toggle('is-busy',rt.busy);
  const last=stats.sessions[0];
  const recentScan=last && Date.now()/1000-last.last<60;
  $('alert').classList.toggle('hidden',!recentScan);
  if(recentScan) setText('alert-text',`${last.confidence==='high'?'检测到 Nmap 特征序列':'发现疑似探测'} · ${last.source} → ${last.target} · ${number(last.probes)} 条摘要`);
  $('alert-protect').disabled=rt.busy || protecting;
  const max=Math.max(1,...Object.values(stats.counts));
  $('probe-bars').innerHTML=names.map(name=>{
    const unavailable=protecting && ['IE1','IE2','U1'].includes(name);
    const count=stats.counts[name]||0;
    return `<div class="probe-bar" title="${escapeHTML(name)} · ${unavailable?'抗测绘模式无此明细；显示历史累计':'硬件特征匹配累计'}"><span>${name}</span><div class="bar-track"><b style="width:${count/max*100}%"></b></div><strong>${number(count)}</strong></div>`;
  }).join('');
  setText('category-total',`${Object.values(stats.counts).filter(x=>x>0).length} 类命中`);
  $('recent-table').innerHTML=eventTable(stats.events.slice(0,5));
  if(view==='events') renderRecords();
  if(view==='overview') drawTrend();
  icons();
}
function empty(message) { return `<div class="empty-state"><i data-lucide="radar"></i>${escapeHTML(message)}</div>`; }
function eventTable(events) {
  if(!events.length) return empty('暂无探针摘要');
  return '<table><thead><tr><th>时间</th><th>来源地址</th><th>受保护主机</th><th>探针</th><th>目标端口</th><th>来源</th></tr></thead><tbody>'+events.map(e=>`<tr><td class="code">${timeText(e.time)}</td><td class="code">${escapeHTML(e.source)}</td><td class="code">${escapeHTML(e.target)}</td><td><span class="probe-label">${escapeHTML(e.category)}</span></td><td class="code">${e.dport||'—'}</td><td>ASIC Digest</td></tr>`).join('')+'</tbody></table>';
}
function renderRecords() {
  if(!state) return;
  const search=$('event-search').value.toLowerCase();
  const records=state.statistics[recordView].filter(e=>Object.values(e).join(' ').toLowerCase().includes(search));
  setText('record-count',`${number(records.length)} 条最近记录`);
  if(recordView==='events') $('events-table').innerHTML=eventTable(records);
  else $('events-table').innerHTML=records.length?'<table><thead><tr><th>开始时间</th><th>最后活动</th><th>来源</th><th>目标</th><th>摘要数量</th><th>置信度</th></tr></thead><tbody>'+records.map(s=>`<tr><td class="code">${timeText(s.first)}</td><td class="code">${timeText(s.last)}</td><td class="code">${escapeHTML(s.source)}</td><td class="code">${escapeHTML(s.target)}</td><td>${number(s.probes)}</td><td><span class="badge ${s.confidence==='high'?'':'warning'}">${s.confidence==='high'?'高置信':'疑似'}</span></td></tr>`).join('')+'</tbody></table>':empty('暂无扫描会话');
  icons();
}
async function poll() {
  if(polling) return;
  polling=true;
  try {
    state=await api('/api/state'); csrf=state.csrf; connectionOK=true;
    setText('connection','已连接'); $('connection').className='badge'; render();
    if(view==='logs' && !$('confirm-dialog').open) await loadLog();
  } catch(error) {
    connectionOK=false; setText('connection','连接断开'); $('connection').className='badge danger';
    if(state) { state.runtime.telemetry.fresh=false; render(); }
  } finally { polling=false; }
}
function confirmDialog(title,description,html,button='确认') {
  return new Promise(resolve=>{
    setText('confirm-title',title);setText('confirm-description',description);$('confirm-content').innerHTML=html;
    $('confirm-ok').querySelector('span').textContent=button;
    const dialog=$('confirm-dialog');
    const finish=answer=>{dialog.close();$('confirm-ok').onclick=null;$('confirm-cancel').onclick=null;dialog.oncancel=null;resolve(answer);};
    $('confirm-ok').onclick=()=>finish(true);$('confirm-cancel').onclick=()=>finish(false);
    dialog.oncancel=e=>{e.preventDefault();finish(false);};
    dialog.showModal();$('confirm-cancel').focus();icons();
  });
}
async function operate(action, selectedMode=mode()) {
  if(modalBusy) return;
  modalBusy=true;render();
  try {
    const prepared=await api('/api/operation/prepare',{method:'POST',body:JSON.stringify({mode:selectedMode,action})});
    if(prepared.confirmation_required) {
      const html=prepared.processes.map(p=>`<div class="process-item"><div><b>${escapeHTML(p.program)} · ${p.plane==='data'?'数据面':'控制面'}</b><span>PID ${p.pid}</span></div><code>${escapeHTML(p.name)}: ${escapeHTML(p.command)}</code></div>`).join('');
      const yes=await confirmDialog(action==='stop'?'停止当前程序？':prepared.processes.length?'发现正在运行的交换机程序':'启动所选模式？',action==='stop'?'确认后将退出下列进程，转发和监测会中断。':`确认后${prepared.processes.length?'退出下列进程，再':''}依次启动 ${selectedMode} 的数据面和控制面。切换期间转发与监测会中断。`,html||empty('未发现运行中的交换机进程'),action==='stop'?'确认停止':prepared.processes.length?'停止并切换':'确认启动');
      if(!yes) {await api('/api/operation/cancel',{method:'POST',body:JSON.stringify({token:prepared.token})});toast('已取消，现有进程保持不变');return;}
    }
    await api('/api/operation/confirm',{method:'POST',body:JSON.stringify({token:prepared.token})});
    toast(action==='stop'?'正在停止程序':'启动任务已提交');await poll();
  } catch(error) {toast(error.message,true);}
  finally {modalBusy=false;render();}
}
async function loadProfiles() {
  try {profileList=(await api('/api/profiles')).profiles;renderProfiles();}catch(error){toast(error.message,true);}
}
function renderProfiles() {
  const query=$('profile-search').value.toLowerCase(),family=$('profile-family').value;
  const list=profileList.filter(p=>[p.name,p.variant||''].join(' ').toLowerCase().includes(query)&&(family==='all'||p.family===family));
  setText('profile-count',`${profileList.length} 个指纹`);
  $('profile-grid').innerHTML=list.length?list.map(p=>`<article class="profile-card ${p.id===state?.selected.id?'selected':''}"><div class="profile-head"><i data-lucide="${p.family==='Windows'?'grid-2x2':p.family==='Mac'?'laptop':'terminal'}"></i><span class="badge ${p.id===state?.selected.id?'':'muted'}">${p.id===state?.selected.id?'已选定':escapeHTML(p.family)}</span></div><h3>${escapeHTML(p.name)}</h3>${p.variant?`<small class="muted-text">${escapeHTML(p.variant)}</small>`:''}<div class="profile-meta"><span>TTL<b>${p.ttl??'—'}</b></span><span>WINDOW<b>${p.window??'—'}</b></span><span>ISN<b>${p.isn} / 6</b></span></div><div class="profile-actions"><button class="button ${p.id===state?.selected.id?'secondary':'primary'}" data-select-profile="${p.id}"><i data-lucide="fingerprint"></i>${p.id===state?.selected.id?'当前指纹':'使用此指纹'}</button><button class="icon-button" data-profile-detail="${p.id}" title="查看指纹 JSON" aria-label="查看指纹 JSON"><i data-lucide="code"></i></button></div></article>`).join(''):empty('没有匹配的指纹');
  icons();
}
async function selectProfile(id) {
  const p=profileList.find(x=>x.id===id);
  if(!p || modalBusy || id===state?.selected.id) return;
  modalBusy=true;
  try {
    const live=state?.runtime.telemetry.fresh && state.runtime.telemetry.program==='antiFpProbe';
    const description=(p.candidate?'此候选已通过格式校验，尚未进行端到端实测。':'')+(live?'当前处于抗测绘模式。确认后控制面将刷新规则，期间存在短暂更新窗口。':'指纹将保存为待生效配置，在启动抗测绘模式后下发。');
    const yes=await confirmDialog('更换目标指纹？',description,`<div class="process-item"><b>${escapeHTML(p.name)}</b><code>${escapeHTML(p.variant||'')} · TTL ${p.ttl} · Window ${p.window} · ${p.isn} ISNs</code></div>`,'确认更换');
    if(!yes) return;
    await api('/api/profiles/select',{method:'POST',body:JSON.stringify({id})});
    toast('指纹已保存，等待控制面确认生效');await poll();renderProfiles();
  } catch(error) {toast(error.message,true);}finally {modalBusy=false;render();}
}
async function loadLog() {
  try {
    if(logView==='audit') setText('log-output',(state?.statistics.audit||[]).map(e=>`${timeText(e.time)}  [${e.action}]  ${e.detail}`).join('\n')||'暂无操作记录');
    else setText('log-output',(await api(`/api/logs/${logView}`)).text||'暂无日志');
  }catch(error){setText('log-output',error.message);}
}
function sizedCanvas(canvas) {
  const box=canvas.getBoundingClientRect(),ratio=Math.min(window.devicePixelRatio||1,2);
  if(!box.width || !box.height) return null;
  const w=Math.round(box.width*ratio),h=Math.round(box.height*ratio);
  if(canvas.width!==w || canvas.height!==h) {canvas.width=w;canvas.height=h;}
  const ctx=canvas.getContext('2d');ctx.setTransform(ratio,0,0,ratio,0,0);
  return {ctx,w:box.width,h:box.height};
}
function drawTrend() {
  const chart=sizedCanvas($('trend-chart'));if(!chart) return;
  const {ctx,w,h}=chart;ctx.clearRect(0,0,w,h);
  const minute=Math.floor(Date.now()/60000)*60;
  const values=Array.from({length:30},(_,i)=>Number(state?.statistics.chart[minute-(29-i)*60]||0));
  const top=Math.max(5,...values),pad=27,bottom=h-8;
  ctx.font='8px Consolas';ctx.textAlign='left';ctx.lineWidth=1;
  for(let i=0;i<4;i++){const y=8+(bottom-8)*i/3;ctx.strokeStyle='#dde7df';ctx.setLineDash([3,4]);ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(w,y);ctx.stroke();ctx.fillStyle='#93a696';ctx.fillText(Math.round(top*(1-i/3)),0,y+3);}
  ctx.setLineDash([]);const points=values.map((v,i)=>[pad+i*(w-pad)/29,bottom-(v/top)*(bottom-12)]);
  ctx.beginPath();ctx.moveTo(points[0][0],bottom);points.forEach(([x,y])=>ctx.lineTo(x,y));ctx.lineTo(w,bottom);ctx.closePath();ctx.fillStyle='#0d927514';ctx.fill();
  ctx.beginPath();points.forEach(([x,y],i)=>i?ctx.lineTo(x,y):ctx.moveTo(x,y));ctx.strokeStyle='#128773';ctx.lineWidth=1.8;ctx.stroke();
  setText('chart-peak',`峰值 ${number(Math.max(...values))}`);
}
function animateTopology(t) {
  if(view==='overview') {
    const scene=sizedCanvas($('topology-canvas'));
    if(scene){const {ctx,w,h}=scene;ctx.clearRect(0,0,w,h);
      ctx.strokeStyle='#63846e10';ctx.lineWidth=1;
      for(let x=0;x<w;x+=25){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,h);ctx.stroke();}
      for(let y=0;y<h;y+=25){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke();}
      const active=connectionOK && state?.runtime.link_ready && !state.runtime.busy;
      const icon=$('scene').querySelector('.device-icon').getBoundingClientRect();
      const y=icon.top-$('scene').getBoundingClientRect().top+icon.height/2;
      const x1=w/6+27,x2=w/2-45,x3=w/2+45,x4=w*5/6-27;
      [[x1,x2],[x3,x4]].forEach(([a,b])=>{
        ctx.strokeStyle=active?'#55966e':'#45604c';ctx.setLineDash([4,5]);ctx.beginPath();ctx.moveTo(a,y);ctx.lineTo(b,y);ctx.stroke();ctx.setLineDash([]);
        ctx.fillStyle=active?'#75eabc':'#71917c';ctx.beginPath();ctx.moveTo(b-5,y-3);ctx.lineTo(b,y);ctx.lineTo(b-5,y+3);ctx.closePath();ctx.fill();
        if(active && !window.matchMedia('(prefers-reduced-motion: reduce)').matches){
          for(let n=0;n<2;n++){const x=a+((t/2600+n/2)%1)*(b-a);ctx.fillStyle='#72eabd';ctx.fillRect(x,y-1.5,8,3);}
        }
      });
    }
  }
  requestAnimationFrame(animateTopology);
}
document.querySelectorAll('[data-view]').forEach(el=>el.onclick=()=>openView(el.dataset.view));
document.querySelectorAll('[data-open]').forEach(el=>el.onclick=()=>openView(el.dataset.open));
document.querySelectorAll('input[name="mode"]').forEach(el=>el.onchange=()=>setText('selected-mode',mode()));
document.querySelectorAll('[data-record]').forEach(el=>el.onclick=()=>{recordView=el.dataset.record;document.querySelectorAll('[data-record]').forEach(x=>x.classList.toggle('active',x===el));renderRecords();});
document.querySelectorAll('[data-log]').forEach(el=>el.onclick=()=>{logView=el.dataset.log;document.querySelectorAll('[data-log]').forEach(x=>x.classList.toggle('active',x===el));loadLog();});
$('login-dialog').addEventListener('cancel',e=>e.preventDefault());
$('login-form').onsubmit=async event=>{event.preventDefault();try{const result=await api('/api/login',{method:'POST',body:JSON.stringify({token:$('access-token').value})});csrf=result.csrf;$('access-token').value='';setText('login-error','');$('login-dialog').close();await poll();}catch(error){setText('login-error','访问码错误或请求失败，请重试');}};
$('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST',body:'{}'});location.reload();}catch(error){toast(error.message,true);}};
$('start').onclick=()=>operate('start');$('stop').onclick=()=>operate('stop');
$('alert-protect').onclick=()=>{document.querySelector('input[value="antiFpProbe"]').checked=true;setText('selected-mode','antiFpProbe');operate('start','antiFpProbe');};
$('choose-profile').onclick=()=>openView('profiles');$('event-search').oninput=renderRecords;
$('profile-search').oninput=renderProfiles;$('profile-family').onchange=renderProfiles;
$('profile-grid').onclick=async event=>{const select=event.target.closest('[data-select-profile]');if(select){selectProfile(select.dataset.selectProfile);return;}const detail=event.target.closest('[data-profile-detail]');if(detail){try{const data=await api(`/api/profiles/${detail.dataset.profileDetail}`);setText('detail-title',data.OS);setText('detail-content',JSON.stringify(data,null,2));$('detail-dialog').showModal();}catch(error){toast(error.message,true);}}};
$('detail-close').onclick=()=>$('detail-dialog').close();
$('import-profile').onclick=()=>$('profile-file').click();
$('profile-file').onchange=async()=>{const file=$('profile-file').files[0];if(!file)return;try{if(file.size>1024*1024)throw new Error('指纹文件不能超过 1 MB');const data=JSON.parse(await file.text());await api('/api/profiles/import',{method:'POST',body:JSON.stringify(data)});toast('指纹校验通过，已加入指纹库');await loadProfiles();}catch(error){toast(error.message,true);}finally{$('profile-file').value='';}};
$('export').onclick=()=>{const anchor=document.createElement('a');anchor.href='/api/export';anchor.download='osdisguise-monitor.json';anchor.click();};
$('refresh-log').onclick=loadLog;
$('fullscreen').onclick=async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await document.documentElement.requestFullscreen();}catch(error){toast('浏览器不支持全屏',true);}};
window.addEventListener('resize',drawTrend);
setInterval(()=>setText('clock',timeText(Date.now()/1000)),1000);
setInterval(poll,2000);icons();poll();requestAnimationFrame(animateTopology);
