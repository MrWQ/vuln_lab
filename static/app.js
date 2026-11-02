const $ = (id) => document.getElementById(id);
const csrf = () => document.cookie.split('; ').find(x => x.startsWith('vkb_csrf='))?.split('=').slice(1).join('=') || '';
async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('X-CSRF-Token', decodeURIComponent(csrf()));
  if (options.body && typeof options.body !== 'string') {
    headers.set('Content-Type', 'application/json');
    options.body = JSON.stringify(options.body);
  }
  const res = await fetch(url, {...options, headers});
  if (res.status === 401) { location.href = '/login'; throw new Error('登录已失效'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `请求失败 (${res.status})`);
  return data;
}
function logout() {
  fetch('/logout', {method: 'POST', headers: {'X-CSRF-Token': decodeURIComponent(csrf())}}).finally(() => location.href = '/login');
}
function setNotice(message, error = false) {
  const n = $('notice'); if (!n) return;
  n.textContent = message; n.classList.remove('hidden', 'error'); if (error) n.classList.add('error');
  window.setTimeout(() => n.classList.add('hidden'), 6500);
}

async function loadCoverage() {
  if (!$('coverage-metrics')) return;
  const metrics = $('coverage-metrics');
  const rows = $('coverage-rows');
  metrics.replaceChildren();
  const loading = document.createElement('div'); loading.className = 'coverage-card muted'; loading.textContent = '正在读取收录概况…'; metrics.append(loading);
  try {
    const data = await api('/api/coverage');
    metrics.replaceChildren();
    const discovered = data.sources.reduce((sum, row) => sum + Number(row.discovered || 0), 0);
    const processed = data.sources.reduce((sum, row) => sum + Number(row.processed || 0), 0);
    const definitions = [
      ['已发布漏洞', data.published_vulnerabilities], ['关联产品', data.published_products],
      ['漏洞-产品关系', data.published_product_links], ['已审核材料', data.approved_materials],
      ['来源分区', data.sources.length], ['分区已发现 / 已处理', `${discovered.toLocaleString()} / ${processed.toLocaleString()}`]
    ];
    for (const [label, value] of definitions) {
      const card = document.createElement('div'); card.className = 'coverage-card';
      const title = document.createElement('span'); title.textContent = label;
      const count = document.createElement('b'); count.textContent = Number.isFinite(Number(value)) ? Number(value).toLocaleString() : value;
      card.append(title, count); metrics.append(card);
    }
    rows.replaceChildren();
    if (!data.sources.length) {
      const tr = document.createElement('tr'); const td = document.createElement('td'); td.colSpan = 7; td.className = 'muted';
      td.textContent = '尚无已登记来源分区。来源历史范围未配置前，不代表该来源已完整扫描。'; tr.append(td); rows.append(tr);
    }
    for (const source of data.sources) {
      const tr = document.createElement('tr');
      for (const value of [source.source, source.partition, source.state, source.discovered, source.processed,
        source.last_sync_at ? new Date(source.last_sync_at).toLocaleString() : '尚未完成', source.error || '—']) {
        const td = document.createElement('td'); td.textContent = value ?? '—'; tr.append(td);
      }
      rows.append(tr);
    }
    const jobs = data.jobs_by_state || {};
    $('coverage-jobs').textContent = `任务队列：待处理 ${jobs.queued || 0} · 运行中 ${jobs.running || 0} · 失败 ${jobs.failed || 0}。历史分区范围和来源配额以来源能力为准。`;
  } catch (error) {
    metrics.replaceChildren(); rows.replaceChildren();
    const card = document.createElement('div'); card.className = 'coverage-card error'; card.textContent = error.message;
    metrics.append(card);
  }
}

let currentCursor = null;
let searchRequestId = 0;
let searchController = null;
let selectedProductId = null;
function searchParams() {
  return {q: $('q')?.value.trim() || '', product: $('product')?.value.trim() || '',
    company: $('company')?.value.trim() || '', version: $('version')?.value.trim() || '',
    product_id: selectedProductId ? String(selectedProductId) : ''};
}
function resultCard(item) {
  const article = document.createElement('article'); article.className = 'result-card';
  const head = document.createElement('div'); head.className = 'result-top';
  const title = document.createElement('a'); title.href = item.url; title.className = 'result-title'; title.textContent = item.title;
  head.append(title);
  const badges = document.createElement('div'); badges.className = 'badge-row';
  for (const value of [item.cve_id, item.vuln_type, `${item.material_count} 份材料`].filter(Boolean)) {
    const tag = document.createElement('span'); tag.className = 'tag'; tag.textContent = value; badges.append(tag);
  }
  article.append(head, badges);
  const summary = document.createElement('p'); summary.className = 'result-summary'; summary.textContent = item.summary || '暂无摘要'; article.append(summary);
  const foot = document.createElement('div'); foot.className = 'result-foot';
  const product = document.createElement('span'); product.textContent = (item.products || []).map(p =>
    `${p.company} / ${p.product} · ${p.material_count} 份适用材料`).join('；') || `${item.company} / ${item.product}`;
  const version = document.createElement('span');
  const versionStatus = item.products?.some(p => p.version_status === 'affected') ? '该版本在漏洞影响范围内' :
    item.products?.some(p => p.version_status === 'unknown') ? '版本或材料适用范围待确认' : `影响版本：${item.version || '未知'}`;
  version.textContent = `版本：${item.version || '未指定'} · ${versionStatus}`;
  const link = document.createElement('a'); link.href = item.url; link.textContent = '查看复现材料 →';
  foot.append(product, version, link); article.append(foot); return article;
}
async function search(append = false, restoreUrl = false) {
  if (!$('results')) return;
  const requestId = ++searchRequestId;
  const params = searchParams();
  renderActiveFilters(params);
  if (!append) currentCursor = null;
  if (append && (!currentCursor || $('load-more')?.disabled)) return;
  const q = new URLSearchParams({...params, limit: '50', ...(append ? {cursor: currentCursor} : {})});
  if (!append) {
    searchController?.abort(); searchController = new AbortController();
    const target = `/?${q.toString()}`;
    if (!restoreUrl && `${location.pathname}${location.search}` !== target) history.pushState({}, '', target);
  } else if ($('load-more')) {
    $('load-more').disabled = true; $('load-more').textContent = '正在加载…';
  }
  if (!append) { const loading = document.createElement('div'); loading.className = 'loading-state'; loading.textContent = '正在搜索已审核的复现材料…'; $('results').replaceChildren(loading); }
  try {
    const data = await api(`/api/search?${q}`, {signal: searchController?.signal});
    if (requestId !== searchRequestId) return;
    if (!append) $('results').replaceChildren();
    if (!data.items.length && !append) {
      const coverage = await api('/api/coverage');
      const empty = document.createElement('div'); empty.className = 'empty-state';
      const icon = document.createElement('span'); icon.className = 'empty-icon'; icon.textContent = '⌕';
      const b = document.createElement('b'); b.textContent = '暂时没有匹配的可复现漏洞';
      const p = document.createElement('p'); p.textContent = `当前库内 ${coverage.published_vulnerabilities} 条漏洞、${coverage.approved_materials} 份审核材料；无结果只表示当前没有匹配的已收录内容，不代表产品不存在漏洞。`;
      empty.append(icon, b, p); $('results').append(empty);
    } else data.items.forEach(item => $('results').append(resultCard(item)));
    $('result-count').textContent = data.total.toLocaleString();
    $('query-summary').textContent = Object.entries(params).filter(([key, value]) => key !== 'product_id' && value)
      .map(([key, value]) => `${({q:'关键词',product:'产品',company:'公司',version:'版本'})[key]}：${value}`).join(' · ') || '全部产品';
    currentCursor = data.next_cursor || null;
    $('load-more').classList.toggle('hidden', !currentCursor);
  } catch (err) { if (err.name !== 'AbortError' && requestId === searchRequestId && $('results')) $('results').textContent = err.message; }
  finally { if (requestId === searchRequestId && $('load-more')) { $('load-more').disabled = false; $('load-more').textContent = '加载更多'; } }
}
function loadMore() { search(true); }
function renderActiveFilters(params) {
  const root = $('active-filters'); if (!root) return;
  root.replaceChildren();
  const labels = {product: '产品', company: '公司', version: '版本', q: '关键词'};
  for (const [key, value] of Object.entries(params)) {
    if (!value || key === 'product_id') continue;
    const chip = document.createElement('button'); chip.type = 'button'; chip.className = 'filter-chip';
    chip.textContent = `${labels[key]}：${value} ×`; chip.setAttribute('aria-label', `移除${labels[key]}筛选 ${value}`);
    chip.addEventListener('click', () => {
      if ($(key)) $(key).value = '';
      if (key === 'product') { selectedProductId = null; $('product').dataset.selectedName = ''; }
      search();
    });
    root.append(chip);
  }
  if (Object.values(params).some(Boolean)) {
    const clear = document.createElement('button'); clear.type = 'button'; clear.className = 'clear-filters';
    clear.textContent = '清空筛选'; clear.addEventListener('click', () => {
      for (const key of ['q','product','company','version']) $(key).value = '';
      selectedProductId = null; $('product').dataset.selectedName = ''; search();
    }); root.append(clear);
  }
}
if ($('results')) {
  const params = new URLSearchParams(location.search);
  for (const key of ['q', 'product', 'company', 'version']) if ($(key)) $(key).value = params.get(key) || '';
  selectedProductId = params.get('product_id') || null;
  $('product').dataset.selectedName = selectedProductId ? $('product').value : '';
  if ([...params.keys()].length) search(false, true);
  ['q', 'company', 'version'].forEach(id => $(id)?.addEventListener('keydown', e => {if (e.key === 'Enter') search();}));
  $('product')?.addEventListener('keydown', e => {if (e.key === 'Enter') search();});
  let suggestionTimer; let composing = false; let suggestionRequestId = 0;
  let suggestionController = null;
  $('product')?.addEventListener('compositionstart', () => { composing = true; suggestionController?.abort(); });
  $('product')?.addEventListener('compositionend', () => {composing = false; suggestProducts();});
  $('product')?.addEventListener('input', () => {
    if (selectedProductId && $('product').value.trim() !== $('product').dataset.selectedName) selectedProductId = null;
    if (!composing) suggestProducts();
  });
  $('product')?.addEventListener('keydown', e => {
    const options = [...$('suggestions').querySelectorAll('[role="option"]')];
    if (e.key === 'ArrowDown' && options.length) { e.preventDefault(); options[0].focus(); }
    if (e.key === 'Escape' && $('suggestions')) { suggestionController?.abort(); $('suggestions').replaceChildren(); $('product').setAttribute('aria-expanded','false'); }
  });
  $('suggestions')?.addEventListener('keydown', e => {
    const options = [...$('suggestions').querySelectorAll('[role="option"]')];
    const current = options.indexOf(document.activeElement);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); const delta = e.key === 'ArrowDown' ? 1 : -1;
      options[(current + delta + options.length) % options.length]?.focus();
    } else if (e.key === 'Escape') { $('suggestions').replaceChildren(); $('product').setAttribute('aria-expanded','false'); $('product').focus(); }
  });
  async function suggestProducts() {
    clearTimeout(suggestionTimer); suggestionTimer = setTimeout(async () => {
      const input = $('product').value.trim(); if (input.length < 2) { $('suggestions').replaceChildren(); $('product').setAttribute('aria-expanded','false'); return; }
      const requestId = ++suggestionRequestId;
      suggestionController?.abort(); suggestionController = new AbortController();
      try {
        const data = await api(`/api/suggest?q=${encodeURIComponent(input)}`, {signal: suggestionController.signal}); if (requestId !== suggestionRequestId || $('product').value.trim() !== input) return; const root = $('suggestions'); root.replaceChildren();
      data.items.forEach(x => { const b = document.createElement('button'); b.type = 'button'; b.className = 'suggestion'; b.setAttribute('role', 'option'); b.textContent = `${x.name}${x.company ? ` · ${x.company}` : ''}${x.matched_alias ? `（匹配别名：${x.matched_alias}）` : ''}`; b.addEventListener('click', () => { $('product').value = x.name; $('product').dataset.selectedName = x.name; selectedProductId = x.id; $('company').value = x.company || ''; root.replaceChildren(); $('product').setAttribute('aria-expanded','false'); search(); }); root.append(b); }); $('product').setAttribute('aria-expanded', String(data.items.length > 0));
      } catch (error) { if (error.name !== 'AbortError') setNotice(`产品建议暂不可用：${error.message}`, true); }
    }, 250);
  }
  window.addEventListener('popstate', () => {
    const state = new URLSearchParams(location.search);
    for (const key of ['q', 'product', 'company', 'version']) $(key).value = state.get(key) || '';
    selectedProductId = state.get('product_id') || null;
    $('product').dataset.selectedName = selectedProductId ? $('product').value : '';
    search(false, true);
  });
  if ($('suggestions').children.length === 0) $('product').setAttribute('aria-expanded','false');
}
if ($('coverage-metrics')) loadCoverage();

async function enqueueSource(source) {
  try {
    const repo = $('github-repo')?.value.trim() || null;
    const budget = Number($('github-budget')?.value || 100);
    const data = await api('/api/admin/jobs', {method: 'POST', body: {source, repo, budget}});
    setNotice(`采集任务 #${data.id} 已入队。请确认 worker 已启动。`);
  } catch (e) { setNotice(e.message, true); }
}
async function discoverGitHub() {
  try {
    const body = {query: $('github-query').value.trim(), pages: Number($('github-pages').value),
      file_budget: Number($('github-search-budget').value)};
    const data = await api('/api/admin/discover/github', {method: 'POST', body});
    setNotice(`GitHub 仓库发现任务 #${data.id} 已入队。`);
  } catch (e) { setNotice(e.message, true); }
}
async function probeSource(source) {
  try {
    const github = source === 'github_repo';
    const data = await api(`/api/admin/probe/${github ? 'github' : 'exploitdb'}`, {
      method: 'POST', body: github ? {source, repo: $('github-repo').value.trim(), budget: 1} : {source, budget: 1}
    });
    setNotice(`来源可访问：${JSON.stringify(data)}`);
  } catch (e) { setNotice(e.message, true); }
}
async function saveAI() {
  try {
    const data = await api('/api/admin/ai', {method: 'PUT', body: {
      name: 'default', base_url: $('ai-url').value.trim(), model: $('ai-model').value.trim(),
      api_key: $('ai-key').value || null, enabled: $('ai-enabled').checked, auto_publish: $('ai-autopublish').checked,
      daily_budget_usd: Number($('ai-budget').value), input_price_per_million: Number($('ai-input-price').value),
      output_price_per_million: Number($('ai-output-price').value)
    }});
    $('ai-key').value = ''; setNotice(`审核配置已保存（API Key: ${data.api_key}）。`);
  } catch (e) { setNotice(e.message, true); }
}
async function testAI() {
  try {
    const data = await api('/api/admin/probe/ai', {method: 'POST', body: {auto_publish: $('ai-autopublish').checked}});
    setNotice(`模型连接成功：${data.model}；JSON 输出格式可用${data.auto_publish ? '，自动发布已启用' : ''}。`);
  } catch (e) { setNotice(e.message, true); }
}
async function publishEntry(id) {
  try { await api(`/api/admin/entries/${id}/publish`, {method: 'POST'}); setNotice('记录已发布。'); setTimeout(() => location.reload(), 700); }
  catch (e) { setNotice(e.message, true); }
}
async function reviewEntry(id) {
  try {
    const data = await api(`/api/admin/entries/${id}/review`, {method: 'POST'});
    setNotice(`${data.queued} 份材料的审核已重新排队。`);
  } catch (e) { setNotice(e.message, true); }
}
async function createUser() {
  try {
    const body = {username: $('new-username').value.trim(), password: $('new-password').value,
      role: $('new-role').value};
    const account = await api('/api/admin/users', {method: 'POST', body});
    setNotice(`账号 ${account.username}（${account.role}）已创建。`);
    $('new-password').value = ''; setTimeout(() => location.reload(), 700);
  } catch (e) { setNotice(e.message, true); }
}
async function runExport() {
  try { const result = await api('/api/admin/export', {method: 'POST'}); setNotice(`导出已生成：${result.generation}（${result.index}）`); }
  catch (e) { setNotice(e.message, true); }
}

document.addEventListener('click', event => {
  const control = event.target.closest('[data-action]');
  if (!control) return;
  switch (control.dataset.action) {
    case 'logout': logout(); break;
    case 'search': search(); break;
    case 'load-more': loadMore(); break;
    case 'coverage': loadCoverage(); break;
    case 'export': runExport(); break;
    case 'probe-source': probeSource(control.dataset.source); break;
    case 'enqueue-source': enqueueSource(control.dataset.source); break;
    case 'discover-github': discoverGitHub(); break;
    case 'save-ai': saveAI(); break;
    case 'test-ai': testAI(); break;
    case 'create-user': createUser(); break;
    case 'reload': location.reload(); break;
    case 'review-entry': reviewEntry(control.dataset.id); break;
    case 'publish-entry': publishEntry(control.dataset.id); break;
  }
});
