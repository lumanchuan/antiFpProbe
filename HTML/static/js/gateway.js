'use strict';
if(window.lucide) lucide.createIcons();
async function gatewayState(){try{const response=await fetch('/api/state',{cache:'no-store'});if(!response.ok)return;const state=await response.json();const process=state.runtime.processes.find(p=>p.plane==='data');document.getElementById('gateway-status').textContent=state.runtime.busy?'模式切换中':process?({scan_monitor:'监测转发运行中',antiFpProbe:'Nmap 抗测绘运行中',p0f:'p0f 抗测绘运行中'}[process.program]||process.program+' 运行中'):'交换机待启动';}catch(_){document.getElementById('gateway-status').textContent='连接待恢复';}}
gatewayState();setInterval(gatewayState,5000);
