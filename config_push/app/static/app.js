// Filtro de devices na lista (nova execucao): texto + vendor
function filterDevices() {
  const q = (document.getElementById('devFilter')?.value || '').toLowerCase();
  const v = (document.getElementById('vendorFilter')?.value || '');
  const t = (document.getElementById('tagFilter')?.value || '');
  document.querySelectorAll('#devlist .devitem').forEach(function (el) {
    const hay = el.getAttribute('data-search') || '';
    const vendor = el.getAttribute('data-vendor') || '';
    const tags = (el.getAttribute('data-tags') || '')
      .split(',')
      .map(function (x) { return x.trim(); })
      .filter(Boolean);
    const okText = hay.includes(q);
    const okVendor = (!v || vendor === v);
    const okTag = (!t || tags.indexOf(t) !== -1);
    const show = okText && okVendor && okTag;
    el.style.display = show ? '' : 'none';
    el.dataset.visible = show ? '1' : '0';
  });
}

// Marca/desmarca os devices que estao visiveis com os filtros atuais
function selectFilteredDevices(checked) {
  document.querySelectorAll('#devlist .devitem').forEach(function (el) {
    if (el.dataset.visible === '0') return;
    const cb = el.querySelector('input[type=checkbox]');
    if (cb) cb.checked = checked;
  });
}

// Mostrar/ocultar saida de um target
function toggleOutput(id) {
  const el = document.getElementById('out-' + id);
  if (el) el.style.display = (el.style.display === 'none' ? '' : 'none');
}

// Mostrar/ocultar o diff de um target
function toggleDiff(id) {
  const el = document.getElementById('diff-' + id);
  if (el) el.style.display = (el.style.display === 'none' ? '' : 'none');
}

// Devices: engrenagem liga o modo de colunas; checkbox ao lado de cada coluna.
// Ao desmarcar, a coluna e' ocultada (fica salvo no navegador).
let _colsEdit = false;
function _devColState() {
  try { return JSON.parse(localStorage.getItem('devcols') || '{}'); } catch (e) { return {}; }
}
function applyDeviceCols() {
  const state = _devColState();
  document.querySelectorAll('th[data-col]').forEach(function (th) {
    const k = th.getAttribute('data-col');
    th.style.display = (state[k] === false && !_colsEdit) ? 'none' : '';
  });
  document.querySelectorAll('td[data-col]').forEach(function (td) {
    const k = td.getAttribute('data-col');
    td.style.display = (state[k] === false) ? 'none' : '';
  });
  document.querySelectorAll('input[data-colchk]').forEach(function (cb) {
    const k = cb.getAttribute('data-colchk');
    cb.checked = state[k] !== false;
    cb.style.display = _colsEdit ? 'inline-block' : 'none';
  });
  const r = document.getElementById('colsReset');
  if (r) r.style.display = _colsEdit ? '' : 'none';
}
function toggleColsEdit() {
  _colsEdit = !_colsEdit;
  applyDeviceCols();
}
function onColChk(cb) {
  const state = _devColState();
  state[cb.getAttribute('data-colchk')] = cb.checked;
  localStorage.setItem('devcols', JSON.stringify(state));
  applyDeviceCols();
}
function resetDeviceCols() {
  localStorage.removeItem('devcols');
  applyDeviceCols();
}
(function () {
  if (document.querySelector('[data-col]')) applyDeviceCols();
})();

// Mostrar/ocultar as evidencias (achados) de conformidade
function toggleFindings(id) {
  const el = document.getElementById('find-' + id);
  if (el) el.style.display = (el.style.display === 'none' ? '' : 'none');
}

// Politica de conformidade: adiciona/remove linhas de regra
function addRuleRow() {
  const box = document.getElementById('ruleRows');
  const tpl = document.getElementById('ruleTpl');
  if (!box || !tpl) return;
  box.appendChild(tpl.content.firstElementChild.cloneNode(true));
}

function removeRuleRow(btn) {
  const row = btn.closest('.rulerow');
  if (row) row.remove();
}

// Device form: filtra modelos pelo vendor e resolve o driver
function filterModels() {
  const vendor = document.getElementById('vendor');
  const model = document.getElementById('model');
  if (!vendor || !model) return;
  const v = vendor.value;
  let anyVisible = false;
  for (const opt of model.options) {
    if (!opt.dataset || !opt.dataset.vendor) continue;
    const show = (opt.dataset.vendor === v);
    opt.hidden = !show;
    opt.disabled = !show;
    if (show) anyVisible = true;
  }
  const cur = model.options[model.selectedIndex];
  if (cur && (cur.hidden || cur.disabled)) model.selectedIndex = 0;
  updateDriver();
}

function updateDriver() {
  const model = document.getElementById('model');
  const hid = document.getElementById('device_type');
  const disp = document.getElementById('driver_display');
  if (!model) return;
  const opt = model.options[model.selectedIndex];
  const driver = (opt && opt.dataset) ? opt.dataset.driver : '';
  if (driver) {
    if (hid) hid.value = driver;
    if (disp) disp.value = driver;
  }
}

(function () {
  if (document.getElementById('vendor') && document.getElementById('model')) {
    filterModels();
  }
})();


// Wizard da nova execucao (3 passos)
function goStep(n) {
  for (let i = 1; i <= 3; i++) {
    const step = document.getElementById('step-' + i);
    const dot = document.getElementById('dot-' + i);
    if (step) step.classList.toggle('active', i === n);
    if (dot) {
      dot.classList.toggle('active', i === n);
      dot.classList.toggle('done', i < n);
    }
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Device form: testa a conexao sem salvar
async function testDevice() {
  const form = document.querySelector('form[action="/devices/save"]');
  const el = document.getElementById('testResult');
  if (!form || !el) return;
  el.className = 'muted';
  el.textContent = 'testando...';
  try {
    const res = await fetch('/devices/test', {
      method: 'POST',
      body: new FormData(form),
      credentials: 'same-origin',
    });
    const data = await res.json();
    if (data.status === 'success') {
      el.className = 'ok';
      el.textContent = 'OK · driver ' + data.driver + (data.output ? ' · ' + data.output : '');
    } else {
      el.className = 'error';
      el.textContent = 'Falha · ' + (data.error || data.status);
    }
  } catch (e) {
    el.className = 'error';
    el.textContent = 'erro no teste: ' + e;
  }
}

// Configuracoes: testa a conexao de uma integracao (librenms/rconfig)
async function testIntegration(source) {
  const el = document.getElementById('res-' + source);
  const url = (document.getElementById(source + '_url') || {}).value || '';
  const token = (document.getElementById(source + '_token') || {}).value || '';
  const verify = document.getElementById(source + '_verify') && document.getElementById(source + '_verify').checked ? '1' : '0';
  if (el) { el.className = 'muted'; el.textContent = el.dataset.testing || '...'; }
  const body = new URLSearchParams({ url: url, token: token, verify: verify });
  try {
    const res = await fetch('/settings/integrations/' + source + '/test', {
      method: 'POST', body: body, credentials: 'same-origin',
    });
    const data = await res.json();
    if (el) {
      if (data.status === 'success') {
        el.className = 'ok';
        el.textContent = 'OK · ' + (data.message || '');
      } else {
        el.className = 'error';
        el.textContent = 'falha · ' + (data.error || data.status);
      }
    }
  } catch (e) {
    if (el) { el.className = 'error'; el.textContent = 'erro: ' + e; }
  }
}

// Polling do status do run (pagina de detalhe)
(function () {
  if (typeof window.RUN_ID === 'undefined') return;
  let timer = null;

  async function refresh() {
    try {
      const res = await fetch('/api/runs/' + window.RUN_ID, { credentials: 'same-origin' });
      if (!res.ok) return;
      const data = await res.json();
      const lbl = function (s) { return (window.STATUS_LABELS && window.STATUS_LABELS[s]) || s; };
      const st = document.getElementById('runStatus');
      if (st) { st.textContent = lbl(data.status); st.className = 'st st-' + data.status; }
      const rc = document.getElementById('runCounts');
      if (rc && data.counts) {
        const tw = rc.dataset.targets || 'alvos';
        rc.textContent = data.targets.length + ' ' + tw + ': ' +
          Object.keys(data.counts).map(function (k) { return lbl(k) + '=' + data.counts[k]; }).join(' · ');
      }
      data.targets.forEach(function (t) {
        const row = document.querySelector('tr[data-id="' + t.id + '"]');
        if (row) {
          const cell = row.querySelector('.tstatus');
          if (cell) cell.innerHTML = '<span class="st st-' + t.status + '">' + lbl(t.status) + '</span>';
          const err = row.querySelector('.terror');
          if (err) err.textContent = t.error || '';
        }
        const out = document.querySelector('#out-' + t.id + ' pre');
        if (out) out.textContent = t.output || '';
        const dif = document.querySelector('#diff-' + t.id + ' pre');
        if (dif && t.diff) dif.textContent = t.diff;
      });
      const done = ['done', 'failed', 'partial', 'rejected', 'canceled'].includes(data.status);
      if (done && timer) { clearInterval(timer); timer = null; }
    } catch (e) { /* ignora */ }
  }

  const runStatus = document.getElementById('runStatus');
  if (runStatus) {
    refresh();
    timer = setInterval(refresh, 2500);
  }
})();
