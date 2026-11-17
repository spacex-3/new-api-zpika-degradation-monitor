const adminState = { csrf: '', data: null, refreshTimer: null }
const autoRefreshDuration = 10 * 60 * 1000

const benchmarkLabels = { pelican: '鹈鹕骑行', candy: '糖果测试', creative: '自由创作' }

function formatDate(value) {
  if (!value) return '尚未运行'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(value))
}

function toast(message) {
  const element = document.querySelector('#toast')
  element.textContent = message
  element.hidden = false
  clearTimeout(toast.timer)
  toast.timer = setTimeout(() => { element.hidden = true }, 2600)
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  if (options.body) headers['Content-Type'] = 'application/json'
  if (options.method && options.method !== 'GET') headers['X-CSRF-Token'] = adminState.csrf
  const response = await fetch(path, { ...options, headers, cache: 'no-store' })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    const error = new Error(data.error || '请求失败')
    error.status = response.status
    throw error
  }
  return data
}

function setAuthenticated(authenticated) {
  document.querySelector('#login-panel').hidden = authenticated
  document.querySelector('#admin-content').hidden = !authenticated
  document.querySelector('#logout').hidden = !authenticated
}

async function bootstrap() {
  try {
    const session = await request('/api/admin/session')
    adminState.csrf = session.csrf_token
    setAuthenticated(true)
    await loadState()
  } catch {
    setAuthenticated(false)
  }
}

async function loadState() {
  try {
    adminState.data = await request('/api/admin/state')
    renderTargets()
    renderFailures()
    const status = document.querySelector('#base-url-status')
    status.textContent = adminState.data.base_url_configured ? '已加密保存。重新填写可替换当前地址。' : '尚未配置。'
    const barkStatus = document.querySelector('#bark-status')
    barkStatus.textContent = adminState.data.bark_configured ? '已启用。重新填写可替换当前地址。' : '尚未启用。'
    document.querySelector('#notify-mode').value = adminState.data.notify_all ? 'all' : 'alerts'
    document.querySelector('#test-bark').disabled = !adminState.data.bark_configured
  } catch (error) {
    if (error.status === 401) setAuthenticated(false)
    else toast(error.message)
  }
}

function renderFailures() {
  const list = document.querySelector('#failure-list')
  list.replaceChildren()
  const failures = adminState.data?.failures || []
  document.querySelector('#failure-empty').hidden = failures.length > 0
  for (const failure of failures) {
    const item = document.createElement('article')
    item.className = 'failure-item'
    const heading = document.createElement('div')
    heading.className = 'failure-heading'
    const name = document.createElement('strong')
    name.textContent = failure.target_name
    const meta = document.createElement('span')
    const attempts = failure.attempt_count > 0 ? ` · ${failure.attempt_count} 次尝试` : ''
    meta.textContent = `${formatDate(failure.finished_at)}${attempts}`
    heading.append(name, meta)
    const detail = document.createElement('p')
    detail.textContent = failure.failure_detail
    item.append(heading, detail)
    list.append(item)
  }
}

function actionButton(label, className, handler, disabled = false) {
  const button = document.createElement('button')
  button.type = 'button'
  button.className = className
  button.textContent = label
  button.disabled = disabled
  button.addEventListener('click', handler)
  return button
}

function renderTargets() {
  const list = document.querySelector('#target-list')
  list.replaceChildren()
  const targets = adminState.data?.targets || []
  document.querySelector('#admin-empty').hidden = targets.length > 0
  for (const target of targets) {
    const row = document.createElement('article')
    row.className = 'admin-target'
    const name = document.createElement('div')
    name.className = 'admin-target-name'
    const title = document.createElement('strong')
    title.textContent = target.name
    const subtitle = document.createElement('span')
    subtitle.textContent = `${benchmarkLabels[target.benchmark]} · ${target.reasoning_effort}${target.service_tier ? ` · ${target.service_tier}` : ''}`
    name.append(title, subtitle)
    const schedule = stat(target.cron_expression, 'Cron')
    const retention = stat(`${target.retain_count} 次`, '结果保留')
    const next = stat(target.running ? '检测中' : formatDate(target.next_run_at), target.enabled ? '下次执行' : '已停用')
    const actions = document.createElement('div')
    actions.className = 'admin-target-actions'
    actions.append(
      actionButton('立即检测', 'button secondary', () => runTarget(target.id), target.running),
      actionButton('编辑', 'button secondary', () => openTarget(target)),
      actionButton('删除', 'button danger', () => deleteTarget(target), target.running),
    )
    row.append(name, schedule, retention, next, actions)
    list.append(row)
  }
}

function stat(value, label) {
  const element = document.createElement('div')
  element.className = 'admin-target-stat'
  const strong = document.createElement('strong')
  strong.textContent = value
  const span = document.createElement('span')
  span.textContent = label
  element.append(strong, span)
  return element
}

function openTarget(target = null) {
  const editing = Boolean(target)
  document.querySelector('#target-dialog-title').textContent = editing ? '编辑检测分组' : '新增检测分组'
  document.querySelector('#target-id').value = target?.id || ''
  document.querySelector('#target-name').value = target?.name || ''
  document.querySelector('#target-benchmark').value = target?.benchmark || 'pelican'
  document.querySelector('#target-effort').value = target?.reasoning_effort || 'low'
  document.querySelector('#target-tier').value = target?.service_tier || ''
  document.querySelector('#target-cron').value = target?.cron_expression || '0 8-22/2 * * *'
  document.querySelector('#target-retain').value = target?.retain_count || 6
  document.querySelector('#target-enabled').checked = target?.enabled ?? true
  document.querySelector('#target-public-visible').checked = target?.public_visible ?? true
  document.querySelector('#target-key').value = ''
  document.querySelector('#target-key').required = !editing
  document.querySelector('#key-hint').textContent = editing ? '留空表示继续使用已保存的 Key。' : 'Key 保存后不会再次显示。'
  document.querySelector('#target-error').textContent = ''
  document.querySelector('#target-dialog').showModal()
}

async function runTarget(id) {
  try {
    await request(`/api/admin/targets/${encodeURIComponent(id)}/run`, { method: 'POST' })
    toast('检测任务已开始')
    await loadState()
  } catch (error) { toast(error.message) }
}

async function deleteTarget(target) {
  if (!window.confirm(`删除“${target.name}”及其全部检测记录？`)) return
  try {
    await request(`/api/admin/targets/${encodeURIComponent(target.id)}`, { method: 'DELETE' })
    toast('分组已删除')
    await loadState()
  } catch (error) { toast(error.message) }
}

document.querySelector('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  const errorElement = document.querySelector('#login-error')
  errorElement.textContent = ''
  try {
    const result = await request('/api/admin/login', {
      method: 'POST', body: JSON.stringify({ token: document.querySelector('#admin-token').value }),
    })
    adminState.csrf = result.csrf_token
    document.querySelector('#admin-token').value = ''
    setAuthenticated(true)
    await loadState()
  } catch (error) { errorElement.textContent = error.message }
})

document.querySelector('#logout').addEventListener('click', async () => {
  try { await request('/api/admin/logout', { method: 'POST' }) } catch {}
  adminState.csrf = ''
  setAuthenticated(false)
})

document.querySelector('#settings-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  const baseURL = document.querySelector('#base-url').value.trim()
  if (!baseURL) return toast('请输入 Base URL')
  try {
    await request('/api/admin/settings', { method: 'PUT', body: JSON.stringify({ base_url: baseURL }) })
    document.querySelector('#base-url').value = ''
    toast('上游地址已更新')
    await loadState()
  } catch (error) { toast(error.message) }
})

document.querySelector('#notification-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  const barkURL = document.querySelector('#bark-url').value.trim()
  if (!barkURL && !adminState.data?.bark_configured) return toast('请输入 Bark 推送地址')
  try {
    await request('/api/admin/notifications', {
      method: 'PUT',
      body: JSON.stringify({ bark_url: barkURL, notify_all: document.querySelector('#notify-mode').value === 'all' }),
    })
    document.querySelector('#bark-url').value = ''
    toast('Bark 通知已更新')
    await loadState()
  } catch (error) { toast(error.message) }
})

document.querySelector('#clear-bark').addEventListener('click', async () => {
  try {
    await request('/api/admin/notifications', { method: 'DELETE' })
    document.querySelector('#bark-url').value = ''
    toast('Bark 通知已关闭')
    await loadState()
  } catch (error) { toast(error.message) }
})

document.querySelector('#test-bark').addEventListener('click', async () => {
  const button = document.querySelector('#test-bark')
  button.disabled = true
  try {
    await request('/api/admin/notifications/test', { method: 'POST' })
    toast('测试通知已发送')
  } catch (error) {
    toast(error.message)
  } finally {
    button.disabled = !adminState.data?.bark_configured
  }
})

document.querySelector('#target-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  const id = document.querySelector('#target-id').value
  const payload = {
    name: document.querySelector('#target-name').value,
    benchmark: document.querySelector('#target-benchmark').value,
    model: 'gpt-6-astra',
    reasoning_effort: document.querySelector('#target-effort').value,
    service_tier: document.querySelector('#target-tier').value,
    interval_minutes: 0,
    cron_expression: document.querySelector('#target-cron').value,
    retain_count: Number(document.querySelector('#target-retain').value),
    enabled: document.querySelector('#target-enabled').checked,
    public_visible: document.querySelector('#target-public-visible').checked,
    api_key: document.querySelector('#target-key').value,
  }
  try {
    await request(id ? `/api/admin/targets/${encodeURIComponent(id)}` : '/api/admin/targets', {
      method: id ? 'PUT' : 'POST', body: JSON.stringify(payload),
    })
    document.querySelector('#target-dialog').close()
    toast(id ? '分组已更新' : '分组已创建')
    await loadState()
  } catch (error) { document.querySelector('#target-error').textContent = error.message }
})

document.querySelector('#new-target').addEventListener('click', () => openTarget())
document.querySelector('#target-close').addEventListener('click', () => document.querySelector('#target-dialog').close())
document.querySelector('#target-cancel').addEventListener('click', () => document.querySelector('#target-dialog').close())
document.querySelector('#target-dialog').addEventListener('click', (event) => {
  if (event.target === event.currentTarget) event.currentTarget.close()
})

bootstrap()

function startAutoRefresh() {
  clearInterval(adminState.refreshTimer)
  const stopAt = Date.now() + autoRefreshDuration
  adminState.refreshTimer = setInterval(() => {
    if (Date.now() >= stopAt) {
      clearInterval(adminState.refreshTimer)
      adminState.refreshTimer = null
      return
    }
    if (!document.querySelector('#admin-content').hidden) loadState()
  }, 30000)
}

startAutoRefresh()
