(() => {
  const $ = (selector) => document.querySelector(selector)
  const state = {
    csrfToken: '',
    routes: [],
    logs: [],
    lastLogId: 0,
    activeClient: null,
    clientLogs: [],
    activityChart: null,
  }

  async function api(url, options = {}) {
    const headers = { ...options.headers }
    if (options.method && options.method !== 'GET' && state.csrfToken) {
      headers['X-CSRF-Token'] = state.csrfToken
    }
    const response = await fetch(url, { ...options, headers })
    const payload = await response.json().catch(() => ({}))
    if (response.status === 401) {
      window.location.assign('/login')
      throw new Error('Authentication required')
    }
    if (!response.ok) {
      const error = new Error(payload.error || `Request failed (${response.status})`)
      error.status = response.status
      throw error
    }
    return payload
  }

  function safeError(error) {
    if ([500, 503].includes(error.status)) return 'The service could not complete the request. Check server configuration and application logs.'
    return error.message || 'Something went wrong.'
  }

  function showError(message) {
    $('#error-message').textContent = message
    $('#dashboard-error').classList.remove('d-none')
  }

  function clearError() {
    $('#dashboard-error').classList.add('d-none')
    $('#error-message').textContent = ''
  }

  function formatDate(value) {
    if (!value) return 'Never'
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? 'Never' : date.toLocaleString()
  }

  function clientKey(clientId) {
    return clientId == null ? '' : String(clientId)
  }

  function levelFor(entry) {
    const level = String(entry.level || 'info').toLowerCase()
    const message = String(entry.message || '')
    if (level === 'error' || /^\s*(?:error|filesystem error|worker error)\b/i.test(message)) return 'error'
    if (['warn', 'warning'].includes(level) || /^\s*(?:warn(?:ing)?|source|destination) directory unavailable\b/i.test(message)) return 'warning'
    if (level === 'success' || /^\s*(copied|sync complete|transfer complete)\s*:/i.test(message)) return 'success'
    return 'info'
  }

  function makeBadge(text, color) {
    const badge = document.createElement('span')
    badge.className = `badge bg-${color}-lt`
    badge.textContent = text
    return badge
  }

  function setWorkerStatus(status) {
    const active = Boolean(status.running || status.run_pending)
    const failed = Boolean(status.last_error)
    $('#worker-value').textContent = failed ? 'Attention' : status.running ? 'Running' : status.run_pending ? 'Starting' : 'Ready'
    $('#worker-caption').textContent = failed ? 'Last transfer reported an error' : status.run_pending ? 'Transfer is queued' : status.running ? 'Transfer in progress' : 'Ready for manual transfer'
    $('#connection-label').textContent = failed ? 'Needs attention' : active ? 'Transfer active' : 'Service ready'
    $('#connection-dot').className = `status-dot${failed ? ' status-error' : active ? ' status-warning' : ' status-dot-live'}`
    $('#run-button').disabled = active || !state.csrfToken
    $('#last-value').textContent = formatDate(status.last_finished)
    $('#last-caption').textContent = status.last_finished ? 'Most recent completed run' : 'No completed transfer recorded'
    $('#log-count').textContent = String(status.log_count ?? state.logs.length)
  }

  function renderRoutes() {
    const body = $('#routes-body')
    const filter = $('#route-search').value.trim().toLowerCase()
    const groups = new Map()
    for (const route of state.routes) {
      const key = clientKey(route.client_id)
      if (!groups.has(key)) groups.set(key, [])
      groups.get(key).push(route)
    }
    const clients = [...groups.entries()].filter(([key, routes]) => {
      const searchable = [key, ...routes.flatMap((route) => [route.source, route.destination, route.filename_regex])].join(' ').toLowerCase()
      return searchable.includes(filter)
    })
    const activeRoutes = state.routes.filter((route) => route.enabled).length
    $('#route-value').textContent = String(activeRoutes)
    $('#client-value').textContent = String(groups.size)
    $('#route-caption').textContent = `${state.routes.length} configured in database`
    $('#route-count').textContent = `${clients.length} client${clients.length === 1 ? '' : 's'} · ${state.routes.length} total routes`
    body.replaceChildren()
    $('#routes-empty').classList.toggle('d-none', clients.length > 0)
    if (!clients.length) {
      body.classList.add('d-none')
      return
    }
    body.classList.remove('d-none')

    for (const [clientId, routes] of clients) {
      const row = document.createElement('tr')
      const clientCell = document.createElement('td')
      const name = document.createElement('span')
      name.className = 'client-name'
      name.textContent = clientId || '(no client ID)'
      const count = document.createElement('span')
      count.className = 'client-route-count'
      count.textContent = `${routes.length} route${routes.length === 1 ? '' : 's'}`
      clientCell.append(name, count)

      const routeCell = document.createElement('td')
      if (routes.length > 1) {
        const details = document.createElement('details')
        details.className = 'route-details'
        const summary = document.createElement('summary')
        summary.textContent = 'View route details'
        const list = document.createElement('ul')
        list.className = 'route-detail-list'
        for (const route of routes) list.append(makeRouteDetail(route))
        details.append(summary, list)
        routeCell.append(details)
      } else {
        routeCell.append(makeRouteDetail(routes[0]))
      }

      const stateCell = document.createElement('td')
      const enabled = routes.filter((route) => route.enabled).length
      if (enabled === routes.length) stateCell.append(makeBadge('All enabled', 'green'))
      else if (enabled === 0) stateCell.append(makeBadge('Disabled', 'secondary'))
      else stateCell.append(makeBadge('Mixed', 'yellow'))

      const actionCell = document.createElement('td')
      actionCell.className = 'text-end'
      const logButton = document.createElement('button')
      logButton.className = 'btn btn-sm btn-outline-secondary route-log-button'
      logButton.type = 'button'
      logButton.dataset.clientId = clientId
      logButton.dataset.noClient = clientId ? 'false' : 'true'
      logButton.setAttribute('aria-label', `View logs for ${clientId || 'client without an ID'}`)
      logButton.innerHTML = '<i class="ti ti-list-details me-1" aria-hidden="true"></i>Logs'
      actionCell.append(logButton)
      row.append(clientCell, routeCell, stateCell, actionCell)
      body.append(row)
    }
  }

  function makeRouteDetail(route) {
    const item = document.createElement('li')
    const source = document.createElement('span')
    source.className = 'route-path'
    source.textContent = route.source || 'Source not set'
    const arrow = document.createElement('span')
    arrow.className = 'route-arrow'
    arrow.textContent = `to ${route.destination || 'Destination not set'}`
    item.append(source, arrow)
    if (route.filename_regex) {
      const pattern = document.createElement('span')
      pattern.className = 'route-path text-secondary'
      pattern.textContent = `Pattern: ${route.filename_regex}`
      item.append(pattern)
    }
    return item
  }

  function filteredLogs(entries, query, level) {
    const normalized = query.trim().toLowerCase()
    return entries.filter((entry) => {
      const matchesLevel = level === 'all' || levelFor(entry) === level
      const text = `${entry.client_id ?? ''} ${entry.message ?? ''} ${entry.timestamp ?? ''}`.toLowerCase()
      return matchesLevel && text.includes(normalized)
    })
  }

  function renderLogRows(container, entries, query = '', level = 'all') {
    container.replaceChildren()
    const visible = filteredLogs(entries, query, level)
    if (!visible.length) {
      const empty = document.createElement('div')
      empty.className = 'empty-state log-empty'
      const icon = document.createElement('i')
      icon.className = 'ti ti-terminal-2'
      const title = document.createElement('strong')
      const detail = document.createElement('span')
      title.textContent = entries.length ? 'No matching activity' : 'No activity yet'
      detail.textContent = entries.length ? 'Adjust the search or level filter.' : 'Transfer events will appear here when available.'
      empty.append(icon, title, detail)
      container.append(empty)
      return
    }
    for (const entry of visible) {
      const row = document.createElement('div')
      const time = document.createElement('time')
      const badgeCell = document.createElement('span')
      const message = document.createElement('span')
      const levelName = levelFor(entry)
      row.className = 'log-row'
      time.className = 'log-time'
      time.dateTime = entry.timestamp || ''
      time.textContent = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '—'
      time.title = formatDate(entry.timestamp)
      badgeCell.append(makeBadge(levelName.toUpperCase(), { info: 'blue', warning: 'yellow', error: 'red', success: 'green' }[levelName]))
      message.className = 'log-message'
      if (entry.client_id != null) {
        const client = document.createElement('span')
        client.className = 'log-client'
        client.textContent = `CLIENT ${entry.client_id}`
        message.append(client)
      }
      message.append(document.createTextNode(entry.message || ''))
      row.append(time, badgeCell, message)
      container.append(row)
    }
  }

  function renderActivityChart() {
    const canvas = $('#activity-chart')
    const empty = $('#chart-empty')
    const unavailable = $('#chart-unavailable')
    const eventCountLabel = $('#chart-event-count')
    if (!canvas || !empty || !unavailable || !eventCountLabel) return
    const hour = new Date()
    hour.setMinutes(0, 0, 0)
    hour.setHours(hour.getHours() - 11)
    const labels = Array.from({ length: 12 }, (_, index) => {
      const tick = new Date(hour.getTime())
      tick.setHours(tick.getHours() + index)
      return tick.toLocaleTimeString([], { hour: 'numeric' })
    })
    const counts = Object.fromEntries(['info', 'success', 'warning', 'error'].map((level) => [level, Array(12).fill(0)]))
    let eventCount = 0

    for (const entry of state.logs) {
      const timestamp = new Date(entry.timestamp)
      if (Number.isNaN(timestamp.getTime())) continue
      timestamp.setMinutes(0, 0, 0)
      const index = Math.floor((timestamp.getTime() - hour.getTime()) / 3600000)
      if (index < 0 || index >= 12) continue
      counts[levelFor(entry)][index] += 1
      eventCount += 1
    }

    eventCountLabel.textContent = `${eventCount} event${eventCount === 1 ? '' : 's'}`
    unavailable.classList.add('d-none')
    if (!eventCount) {
      if (state.activityChart) state.activityChart.destroy()
      state.activityChart = null
      canvas.classList.add('d-none')
      empty.classList.remove('d-none')
      return
    }

    empty.classList.add('d-none')
    if (!window.Chart) {
      canvas.classList.add('d-none')
      unavailable.classList.remove('d-none')
      return
    }
    canvas.classList.remove('d-none')
    const muted = getComputedStyle(document.documentElement).getPropertyValue('--ops-muted').trim()
    const border = getComputedStyle(document.documentElement).getPropertyValue('--ops-border').trim()
    const datasets = [
      ['info', 'Info', '#3978d5'],
      ['success', 'Success', '#2a9b72'],
      ['warning', 'Warning', '#d5952f'],
      ['error', 'Error', '#d45454'],
    ].map(([key, label, color]) => ({
      label,
      data: counts[key],
      backgroundColor: color,
      borderColor: color,
      borderRadius: 4,
      borderSkipped: false,
      maxBarThickness: 24,
    }))
    const options = {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', align: 'end', labels: { color: muted, usePointStyle: true, pointStyle: 'circle', boxWidth: 7, boxHeight: 7, padding: 16 } },
        tooltip: { callbacks: { footer: (items) => `${items.reduce((sum, item) => sum + item.raw, 0)} total events` } },
      },
      scales: {
        x: { stacked: true, grid: { display: false }, ticks: { color: muted, maxRotation: 0, autoSkip: true, maxTicksLimit: 12 } },
        y: { stacked: true, beginAtZero: true, grid: { color: border }, ticks: { color: muted, precision: 0, stepSize: 1 } },
      },
    }

    if (!state.activityChart) {
      state.activityChart = new window.Chart(canvas, { type: 'bar', data: { labels, datasets }, options })
    } else {
      state.activityChart.data.labels = labels
      state.activityChart.data.datasets = datasets
      state.activityChart.options = options
      state.activityChart.update('none')
    }
  }

  function renderLogs() {
    const container = $('#log-list')
    renderLogRows(container, state.logs, $('#log-search').value, $('#level-filter').value)
    renderActivityChart()
    $('#last-updated').textContent = `Updated ${new Date().toLocaleTimeString()}`
    if (state.logs.length) container.scrollTop = container.scrollHeight
  }

  async function refreshStatus() {
    const status = await api('/api/status')
    setWorkerStatus(status)
  }

  async function refreshRoutes() {
    const routes = await api('/api/routes')
    if (!Array.isArray(routes)) throw new Error('The route service returned an unexpected response.')
    state.routes = routes
    renderRoutes()
  }

  async function refreshLogs(fromBeginning = false) {
    const after = fromBeginning ? 0 : state.lastLogId
    const entries = await api(`/api/logs?after=${after}`)
    if (fromBeginning) state.logs = entries
    else state.logs.push(...entries)
    if (entries.length) state.lastLogId = Math.max(state.lastLogId, ...entries.map((entry) => Number(entry.id) || 0))
    if (state.logs.length > 500) state.logs = state.logs.slice(-500)
    renderLogs()
    $('#log-count').textContent = String(state.logs.length)
  }

  async function refreshDashboard() {
    clearError()
    const results = await Promise.allSettled([refreshStatus(), refreshRoutes(), refreshLogs(true)])
    const failed = results.find((result) => result.status === 'rejected')
    if (failed) showError(safeError(failed.reason))
  }

  async function openClientLog(button) {
    state.activeClient = { id: button.dataset.clientId, noClient: button.dataset.noClient === 'true' }
    state.clientLogs = []
    const title = state.activeClient.noClient ? 'Client without an ID' : `Client ${state.activeClient.id}`
    $('#client-log-title').textContent = `${title} logs`
    $('#client-log-search').value = ''
    renderLogRows($('#client-log-list'), [])
    $('#client-log-dialog').showModal()
    await refreshClientLog()
  }

  async function refreshClientLog() {
    if (!state.activeClient) return
    try {
      const client = state.activeClient
      const query = client.noClient ? '' : `?client_id=${encodeURIComponent(client.id)}`
      const entries = await api(`/api/logs${query}`)
      state.clientLogs = client.noClient ? entries.filter((entry) => entry.client_id == null) : entries
      renderLogRows($('#client-log-list'), state.clientLogs, $('#client-log-search').value)
      $('#client-log-list').scrollTop = $('#client-log-list').scrollHeight
    } catch (error) {
      renderLogRows($('#client-log-list'), [{ message: safeError(error), level: 'error' }])
    }
  }

  function setTheme(theme) {
    document.documentElement.dataset.bsTheme = theme
    try {
      localStorage.setItem('sftp-dashboard-theme', theme)
    } catch {
      // Theme still works for this page when storage is unavailable.
    }
    const button = $('#theme-toggle')
    button.innerHTML = theme === 'dark' ? '<i class="ti ti-sun"></i>' : '<i class="ti ti-moon"></i>'
    button.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`)
    renderActivityChart()
  }

  function setSidebar(open) {
    document.body.classList.toggle('sidebar-open', open)
    $('#sidebar-toggle').setAttribute('aria-expanded', String(open))
  }

  $('#routes-body').addEventListener('click', (event) => {
    const button = event.target.closest('.route-log-button')
    if (button) openClientLog(button)
  })
  $('#route-search').addEventListener('input', renderRoutes)
  $('#log-search').addEventListener('input', renderLogs)
  $('#level-filter').addEventListener('change', renderLogs)
  $('#refresh-button').addEventListener('click', refreshDashboard)
  $('#logs-refresh').addEventListener('click', () => refreshLogs(true).catch((error) => showError(safeError(error))))
  $('#logs-clear').addEventListener('click', () => {
    state.logs = []
    renderLogs()
    $('#log-count').textContent = '0'
  })
  $('#run-button').addEventListener('click', async () => {
    $('#run-button').disabled = true
    clearError()
    try {
      await api('/api/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      await Promise.allSettled([refreshStatus(), refreshLogs()])
    } catch (error) {
      showError(safeError(error))
      $('#run-button').disabled = false
    }
  })
  $('#dismiss-error').addEventListener('click', clearError)
  $('#close-client-log').addEventListener('click', () => $('#client-log-dialog').close())
  $('#client-log-dialog').addEventListener('click', (event) => {
    if (event.target === $('#client-log-dialog')) $('#client-log-dialog').close()
  })
  $('#refresh-client-log').addEventListener('click', refreshClientLog)
  $('#client-log-search').addEventListener('input', () => renderLogRows($('#client-log-list'), state.clientLogs, $('#client-log-search').value))
  $('#theme-toggle').addEventListener('click', () => setTheme(document.documentElement.dataset.bsTheme === 'dark' ? 'light' : 'dark'))
  $('#sidebar-toggle').addEventListener('click', () => setSidebar(!document.body.classList.contains('sidebar-open')))
  $('#mobile-menu').addEventListener('click', () => setSidebar(true))
  $('#sidebar-backdrop').addEventListener('click', () => setSidebar(false))
  document.querySelectorAll('#sidebar-menu .nav-link').forEach((link) => link.addEventListener('click', () => setSidebar(false)))

  async function initialize() {
    try {
      state.csrfToken = $('#logout-csrf').value
      const results = await Promise.allSettled([refreshStatus(), refreshRoutes(), refreshLogs(true)])
      const failed = results.find((result) => result.status === 'rejected')
      if (failed) showError(safeError(failed.reason))
    } catch (error) {
      showError(safeError(error))
    }
  }

  try {
    const savedTheme = localStorage.getItem('sftp-dashboard-theme')
    setTheme(savedTheme === 'dark' ? 'dark' : 'light')
  } catch {
    setTheme('light')
  }
  initialize()
  window.setInterval(() => {
    refreshStatus().catch((error) => showError(safeError(error)))
    refreshLogs().catch((error) => showError(safeError(error)))
    if ($('#client-log-dialog').open) refreshClientLog()
  }, 3000)
  window.setInterval(() => refreshRoutes().catch((error) => showError(safeError(error))), 15000)
})()
