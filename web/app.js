const state = { data: null, filter: 'all', refreshTimer: null }
const autoRefreshDuration = 10 * 60 * 1000
const embedded = window.location.pathname === '/embed'
let parentOrigin = ''

if (embedded) {
  document.body.classList.add('embedded')
  try {
    parentOrigin = new URL(document.referrer).origin
  } catch {}
}

const benchmarkLabels = {
  pelican: '鹈鹕骑行',
  candy: '糖果测试',
  creative: '自由创作',
}

function formatDate(value) {
  if (!value) return '尚未运行'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(value))
}

function formatDuration(ms) {
  if (!ms) return '-'
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

function formatTokens(value) {
  return new Intl.NumberFormat('zh-CN').format(value || 0)
}

function badgeFor(result) {
  const badge = document.createElement('span')
  badge.className = 'badge'
  const quality = result.quality || result.status
  if (quality === 'normal' || quality === 'passed') {
    badge.classList.add('success')
    badge.textContent = result.label || '正常'
  } else if (quality === 'degraded' || quality === 'suspicious' || quality === 'incorrect') {
    badge.classList.add('warning')
    badge.textContent = result.label || '疑似降智'
  } else if (result.status === 'failed' || quality === 'error') {
    badge.classList.add('danger')
    badge.textContent = '检测失败'
  } else {
    badge.textContent = result.label || result.status
  }
  return badge
}

function renderFilters(targets) {
  const container = document.querySelector('#filters')
  container.replaceChildren()
  const options = [{ id: 'all', name: '全部分组' }, ...targets]
  for (const option of options) {
    const button = document.createElement('button')
    button.type = 'button'
    button.className = `filter-button${state.filter === option.id ? ' active' : ''}`
    button.textContent = option.name
    button.setAttribute('role', 'tab')
    button.setAttribute('aria-selected', String(state.filter === option.id))
    button.addEventListener('click', () => {
      state.filter = option.id
      render()
    })
    container.append(button)
  }
}

function renderTargets(targets) {
  const strip = document.querySelector('#target-strip')
  strip.replaceChildren()
  for (const target of targets) {
    const item = document.createElement('article')
    item.className = 'target-chip'
    const row = document.createElement('div')
    row.className = 'target-status-row'
    const name = document.createElement('strong')
    name.textContent = target.name
    const badge = document.createElement('span')
    badge.className = `badge${target.running ? ' success' : ''}`
    badge.textContent = target.running ? '检测中' : benchmarkLabels[target.benchmark] || target.benchmark
    row.append(name, badge)
    const schedule = document.createElement('small')
    schedule.textContent = target.running ? '正在生成并评估结果' : `下次 ${formatDate(target.next_run_at)}`
    item.append(row, schedule)
    strip.append(item)
  }
}

function historyStatus(result) {
  if (result.status === 'failed' || result.quality === 'error') return 'failed'
  if (['degraded', 'suspicious', 'incorrect'].includes(result.quality)) return 'degraded'
  return 'normal'
}

function renderHistory(history) {
  const entries = history.slice(0, 60).reverse()
  const track = document.querySelector('#history-track')
  const fragments = []
  for (const entry of entries) {
    const status = historyStatus(entry)
    const marker = document.createElement('span')
    marker.className = `history-marker ${status}`
    const statusText = status === 'normal' ? '不降智' : (status === 'degraded' ? '降智' : '请求失败')
    const attempts = entry.attempt_count > 1 ? `\n尝试次数：${entry.attempt_count}` : ''
    const description = [
      `检测时间：${formatDate(entry.finished_at)}`,
      `检测分组：${entry.target_name}`,
      `检测结果：${statusText}`,
      `耗时：${formatDuration(entry.duration_ms)}`,
      `输入 Token：${formatTokens(entry.input_tokens)}`,
      `输出 Token：${formatTokens(entry.output_tokens)}${attempts}`,
    ].join('\n')
    marker.title = description
    marker.setAttribute('role', 'img')
    marker.setAttribute('aria-label', description)
    fragments.push(marker)
  }
  track.replaceChildren(...fragments)
  document.querySelector('#history-count').textContent = `${entries.length} 次`
  document.querySelector('.history-monitor').hidden = entries.length === 0
  track.scrollLeft = track.scrollWidth
}

function createResultCard(result) {
  const card = document.createElement('article')
  card.className = 'result-card'
  if ((result.benchmark === 'pelican' || result.benchmark === 'creative') && result.status === 'succeeded') {
    const preview = document.createElement('div')
    preview.className = 'artifact-preview'
    const frame = document.createElement('iframe')
    frame.className = 'artifact-frame'
    frame.loading = 'lazy'
    frame.sandbox = 'allow-scripts'
    frame.scrolling = 'no'
    frame.tabIndex = -1
    frame.title = `${result.target_name} ${benchmarkLabels[result.benchmark]}结果`
    frame.src = `/api/public/results/${encodeURIComponent(result.id)}/artifact`
    preview.append(frame)
    card.append(preview)
  } else {
    const placeholder = document.createElement('div')
    placeholder.className = 'artifact-placeholder'
    placeholder.textContent = result.benchmark === 'candy' ? '糖果测试结果' : (result.error || '暂无可预览作品')
    card.append(placeholder)
  }

  const content = document.createElement('div')
  content.className = 'card-content'
  const heading = document.createElement('div')
  heading.className = 'card-heading'
  const title = document.createElement('div')
  const name = document.createElement('strong')
  name.textContent = result.target_name
  const time = document.createElement('time')
  time.dateTime = result.finished_at
  time.textContent = formatDate(result.finished_at)
  title.append(name, time)
  heading.append(title, badgeFor(result))

  const meta = document.createElement('div')
  meta.className = 'result-meta'
  for (const text of [result.model, result.reasoning_effort, formatDuration(result.duration_ms), `${formatTokens(result.input_tokens + result.output_tokens)} tokens`]) {
    const item = document.createElement('span')
    item.textContent = text
    meta.append(item)
  }
  content.append(heading, meta)
  if (result.reason || result.error) {
    const reason = document.createElement('p')
    reason.className = 'result-reason'
    reason.textContent = result.reason || result.error
    content.append(reason)
  }
  const action = document.createElement('button')
  action.type = 'button'
  action.className = 'button secondary card-action'
  action.textContent = '查看详情'
  action.addEventListener('click', () => showDetail(result))
  content.append(action)
  card.append(content)
  return card
}

async function showDetail(summary) {
  const dialog = document.querySelector('#detail-dialog')
  const body = document.querySelector('#detail-body')
  document.querySelector('#detail-title').textContent = summary.target_name
  document.querySelector('#detail-time').textContent = `${benchmarkLabels[summary.benchmark] || summary.benchmark} · ${formatDate(summary.finished_at)}`
  body.textContent = '正在读取详情'
  dialog.showModal()
  try {
    const response = await fetch(`/api/public/results/${encodeURIComponent(summary.id)}`, { cache: 'no-store' })
    if (!response.ok) throw new Error('读取详情失败')
    const result = await response.json()
    body.replaceChildren()
    if ((result.benchmark === 'pelican' || result.benchmark === 'creative') && result.status === 'succeeded') {
      const artifactURL = `/api/public/results/${encodeURIComponent(result.id)}/artifact`
      const tabs = document.createElement('div')
      tabs.className = 'detail-tabs'
      tabs.setAttribute('role', 'tablist')

      const previewTab = document.createElement('button')
      previewTab.type = 'button'
      previewTab.className = 'detail-tab active'
      previewTab.textContent = '作品预览'
      previewTab.setAttribute('role', 'tab')
      previewTab.setAttribute('aria-selected', 'true')
      previewTab.setAttribute('aria-controls', 'detail-preview-panel')
      const codeTab = document.createElement('button')
      codeTab.type = 'button'
      codeTab.className = 'detail-tab'
      codeTab.textContent = 'HTML 代码'
      codeTab.setAttribute('role', 'tab')
      codeTab.setAttribute('aria-selected', 'false')
      codeTab.setAttribute('aria-controls', 'detail-code-panel')
      tabs.append(previewTab, codeTab)

      const previewPanel = document.createElement('div')
      previewPanel.id = 'detail-preview-panel'
      previewPanel.className = 'detail-panel'
      previewPanel.setAttribute('role', 'tabpanel')
      const frame = document.createElement('iframe')
      frame.className = 'detail-artifact'
      frame.sandbox = 'allow-scripts'
      frame.title = '检测作品详情'
      frame.src = artifactURL
      previewPanel.append(frame)

      const codePanel = document.createElement('div')
      codePanel.id = 'detail-code-panel'
      codePanel.className = 'detail-panel'
      codePanel.setAttribute('role', 'tabpanel')
      codePanel.hidden = true
      const codeBlock = document.createElement('pre')
      codeBlock.className = 'artifact-code'
      const code = document.createElement('code')
      code.textContent = '正在读取代码'
      codeBlock.append(code)
      codePanel.append(codeBlock)

      const views = [[previewTab, previewPanel], [codeTab, codePanel]]
      for (const [tab, panel] of views) {
        tab.addEventListener('click', () => {
          for (const [candidateTab, candidatePanel] of views) {
            const active = candidateTab === tab
            candidateTab.classList.toggle('active', active)
            candidateTab.setAttribute('aria-selected', String(active))
            candidatePanel.hidden = !active
          }
        })
      }

      body.append(tabs, previewPanel, codePanel)
      fetch(artifactURL, { cache: 'no-store' })
        .then((artifactResponse) => {
          if (!artifactResponse.ok) throw new Error()
          return artifactResponse.text()
        })
        .then((html) => { code.textContent = html })
        .catch(() => { code.textContent = '代码读取失败' })
    }
    if (result.answer) {
      const answer = document.createElement('div')
      answer.className = 'answer'
      answer.textContent = result.answer
      body.append(answer)
    }
  } catch (error) {
    body.textContent = error.message
  }
}

function render() {
  if (!state.data) return
  const targets = state.data.targets || []
  const results = (state.data.results || []).filter((item) => state.filter === 'all' || item.target_id === state.filter)
  renderFilters(targets)
  renderTargets(targets)
  renderHistory(state.data.history || [])
  const grid = document.querySelector('#results')
  grid.replaceChildren(...results.map(createResultCard))
  document.querySelector('#empty').hidden = results.length > 0
  const running = targets.filter((item) => item.running).length
  document.querySelector('#summary').textContent = running > 0 ? `${running} 个分组正在检测` : `${targets.length} 个分组 · ${(state.data.results || []).length} 条记录`
}

async function load() {
  const refresh = document.querySelector('#refresh')
  refresh.disabled = true
  try {
    const response = await fetch('/api/public/state', { cache: 'no-store' })
    if (!response.ok) throw new Error('读取失败')
    state.data = await response.json()
    if (state.filter !== 'all' && !state.data.targets.some((item) => item.id === state.filter)) state.filter = 'all'
    render()
  } catch {
    document.querySelector('#summary').textContent = '暂时无法读取检测记录'
  } finally {
    refresh.disabled = false
  }
}

function startAutoRefresh() {
  clearInterval(state.refreshTimer)
  const stopAt = Date.now() + autoRefreshDuration
  state.refreshTimer = setInterval(() => {
    if (Date.now() >= stopAt) {
      clearInterval(state.refreshTimer)
      state.refreshTimer = null
      return
    }
    load()
  }, 30000)
}

document.querySelector('#refresh').addEventListener('click', () => {
  startAutoRefresh()
  load()
})
document.querySelector('#detail-close').addEventListener('click', () => document.querySelector('#detail-dialog').close())
document.querySelector('#detail-dialog').addEventListener('click', (event) => {
  if (event.target === event.currentTarget) event.currentTarget.close()
})
window.addEventListener('message', (event) => {
  if (
    embedded && parentOrigin && event.source === window.parent && event.origin === parentOrigin &&
    event.data?.source === 'new-api' && event.data?.type === 'theme' &&
    ['light', 'dark'].includes(event.data.theme)
  ) {
    document.documentElement.dataset.theme = event.data.theme
  }
})

if (embedded && parentOrigin) {
  window.parent.postMessage({ source: 'degradation-monitor', type: 'ready' }, parentOrigin)
}

load()
startAutoRefresh()
