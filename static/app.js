// app.js

// State management
let state = {
    activeTab: 'explorer', // 'explorer' or 'analytics'
    filters: {
        table: 'all',
        exporter: '',
        src: '',
        dst: '',
        sport: '',
        dport: '',
        proto: '',
        timeRange: '24h' // linked to top-right select
    },
    pagination: {
        limit: 50,
        offset: 0,
        total: 0
    },
    sorting: {
        by: 'ts',
        order: 'desc'
    },
    records: [], // Cache for current page records
    charts: {}   // Store Chart.js instances
};

// UI Elements
const els = {
    btnTabExplorer: document.getElementById('btn-tab-explorer'),
    btnTabAnalytics: document.getElementById('btn-tab-analytics'),
    btnTabSettings: document.getElementById('btn-tab-settings'),
    viewExplorer: document.getElementById('view-explorer'),
    viewAnalytics: document.getElementById('view-analytics'),
    viewSettings: document.getElementById('view-settings'),
    cleanupBeforeDate: document.getElementById('cleanup-before-date'),
    btnExecuteCleanup: document.getElementById('btn-execute-cleanup'),
    cleanupStatusMessage: document.getElementById('cleanup-status-message'),
    globalTimeRange: document.getElementById('global-time-range'),
    btnRefresh: document.getElementById('btn-refresh'),
    timeRangeSummary: document.getElementById('time-range-summary'),
    
    // KPIs
    kpiTotalFlows: document.getElementById('kpi-total-flows'),
    kpiTotalBytes: document.getElementById('kpi-total-bytes'),
    kpiTotalPackets: document.getElementById('kpi-total-packets'),
    kpiTotalExporters: document.getElementById('kpi-total-exporters'),
    
    // Filters Form
    filterForm: document.getElementById('filter-form'),
    filterSrc: document.getElementById('filter-src'),
    filterDst: document.getElementById('filter-dst'),
    filterSport: document.getElementById('filter-sport'),
    filterDport: document.getElementById('filter-dport'),
    btnResetFilters: document.getElementById('btn-reset-filters'),
    filterProtoGroup: document.getElementById('filter-proto-group'),
    
    // Table
    flowsTbody: document.getElementById('flows-tbody'),
    flowRangeStart: document.getElementById('flow-range-start'),
    flowRangeEnd: document.getElementById('flow-range-end'),
    flowTotalFiltered: document.getElementById('flow-total-filtered'),
    pageSize: document.getElementById('page-size'),
    flowsPagination: document.getElementById('flows-pagination'),
    
    // Modal
    detailsModal: document.getElementById('details-modal'),
    btnCloseModal: document.getElementById('btn-close-modal'),
    detailId: document.getElementById('detail-id'),
    detailTs: document.getElementById('detail-ts'),
    detailType: document.getElementById('detail-type'),
    detailExporter: document.getElementById('detail-exporter'),
    detailSrc: document.getElementById('detail-src'),
    detailSrcDomain: document.getElementById('detail-src-domain'),
    detailDst: document.getElementById('detail-dst'),
    detailDstDomain: document.getElementById('detail-dst-domain'),
    detailProto: document.getElementById('detail-proto'),
    detailOctets: document.getElementById('detail-octets'),
    detailPackets: document.getElementById('detail-packets'),
    detailRawJson: document.getElementById('detail-raw-json')
};

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    // Re-initialize Lucide Icons
    lucide.createIcons();
    
    setupEventListeners();
    setupHeaderSorting();
    updateHeaderSortIcons();
    setupColumnToggles();
    setupDropdowns();
    fetchExporterDropdown();
    refreshData();
});

// Setup Event Listeners
function setupEventListeners() {
    // Tabs Navigation
    els.btnTabExplorer.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('explorer');
    });
    
    els.btnTabAnalytics.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('analytics');
    });

    els.btnTabSettings.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('settings');
    });

    els.btnExecuteCleanup.addEventListener('click', () => {
        executeCleanup();
    });
    
    // Global actions
    els.globalTimeRange.addEventListener('change', () => {
        const value = els.globalTimeRange.value;
        state.filters.timeRange = value;
        
        const customWrapper = document.getElementById('global-custom-time-wrapper');
        if (value === 'custom') {
            customWrapper.style.display = 'flex';
        } else {
            customWrapper.style.display = 'none';
            // Clear custom start/end times in state and inputs when switching back to relative
            state.filters.startTime = '';
            state.filters.endTime = '';
            document.getElementById('global-start-time').value = '';
            document.getElementById('global-end-time').value = '';
        }
        
        updateTimeRangeSubtitle();
        state.pagination.offset = 0; // Reset pagination
        refreshData();
    });

    const globalStart = document.getElementById('global-start-time');
    const globalEnd = document.getElementById('global-end-time');
    
    globalStart.addEventListener('change', () => {
        state.filters.startTime = toUtcTimestamp(globalStart.value);
        state.pagination.offset = 0; // Reset pagination
        updateTimeRangeSubtitle();
        refreshData();
    });
    
    globalEnd.addEventListener('change', () => {
        state.filters.endTime = toUtcTimestamp(globalEnd.value);
        state.pagination.offset = 0; // Reset pagination
        updateTimeRangeSubtitle();
        refreshData();
    });
    
    els.btnRefresh.addEventListener('click', () => {
        // Spin icon on refresh (handles SVG and legacy element tags)
        const icon = els.btnRefresh.querySelector('svg, i, .lucide');
        if (icon) {
            icon.classList.add('spin-animation');
            setTimeout(() => icon.classList.remove('spin-animation'), 1000);
        }
        refreshData();
    });
    
    // Filters form submit & reset
    els.filterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        applyFiltersFromForm();
        state.pagination.offset = 0;
        refreshData();
    });
    
    els.btnResetFilters.addEventListener('click', () => {
        els.filterForm.reset();
        // Reset all custom checkboxes to checked by default
        const checkboxes = document.querySelectorAll('.custom-dropdown input[type="checkbox"]');
        checkboxes.forEach(cb => cb.checked = true);
        applyFiltersFromForm();
        updateDropdownLabels();
        state.pagination.offset = 0;
        refreshData();
    });
    
    // Page size dropdown
    els.pageSize.addEventListener('change', () => {
        state.pagination.limit = parseInt(els.pageSize.value);
        state.pagination.offset = 0;
        fetchFlows();
    });
    
    // CSV Export button
    const btnExportCsv = document.getElementById('btn-export-csv');
    if (btnExportCsv) {
        btnExportCsv.addEventListener('click', () => {
            const params = getFlowQueryParams();
            window.location.href = `/api/flows/export?${params.toString()}`;
        });
    }
    
    // Details modal close
    els.btnCloseModal.addEventListener('click', closeModal);
    els.detailsModal.addEventListener('click', (e) => {
        if (e.target === els.detailsModal) {
            closeModal();
        }
    });
    
    // Close modal on ESC key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && els.detailsModal.classList.contains('active')) {
            closeModal();
        }
    });
}

// Tab Switching logic
function switchTab(tabName) {
    state.activeTab = tabName;
    
    // Hide filter card if settings tab is active
    const filterCard = document.querySelector('.filter-card');
    if (filterCard) {
        filterCard.style.display = tabName === 'settings' ? 'none' : 'block';
    }
    
    const columnsDropdown = document.getElementById('dropdown-columns');
    if (columnsDropdown) {
        const formGroup = columnsDropdown.closest('.form-group');
        if (formGroup) {
            formGroup.style.display = tabName === 'explorer' ? 'block' : 'none';
        }
    }
    
    // Remove active from all tabs and views
    els.btnTabExplorer.classList.remove('active');
    els.btnTabAnalytics.classList.remove('active');
    els.btnTabSettings.classList.remove('active');
    
    els.viewExplorer.classList.remove('active');
    els.viewAnalytics.classList.remove('active');
    els.viewSettings.classList.remove('active');
    
    // Activate selected tab and view
    if (tabName === 'explorer') {
        els.btnTabExplorer.classList.add('active');
        els.viewExplorer.classList.add('active');
        refreshData();
    } else if (tabName === 'analytics') {
        els.btnTabAnalytics.classList.add('active');
        els.viewAnalytics.classList.add('active');
        refreshData();
    } else if (tabName === 'settings') {
        els.btnTabSettings.classList.add('active');
        els.viewSettings.classList.add('active');
    }
}

// Update time summary subtitle
function updateTimeRangeSubtitle() {
    const range = state.filters.timeRange;
    let label = 'Overview of the last 24 hours of traffic';
    if (range === '1h') label = 'Overview of the last 1 hour of traffic';
    if (range === '7d') label = 'Overview of the last 7 days of traffic';
    if (range === 'all') label = 'Overview of all recorded traffic';
    if (range === 'custom') {
        const startVal = document.getElementById('global-start-time').value;
        const endVal = document.getElementById('global-end-time').value;
        if (startVal && endVal) {
            label = `Overview of traffic from ${startVal.replace('T', ' ')} to ${endVal.replace('T', ' ')}`;
        } else {
            label = 'Overview of traffic for specific custom time window';
        }
    }
    els.timeRangeSummary.innerText = label;
}

// Read form elements into state filters
function applyFiltersFromForm() {
    state.filters.table = getSelectedTables();
    state.filters.exporter = getSelectedExporters();
    state.filters.src = els.filterSrc.value.trim();
    state.filters.dst = els.filterDst.value.trim();
    state.filters.sport = els.filterSport.value.trim();
    state.filters.dport = els.filterDport.value.trim();
    state.filters.proto = getSelectedProtocols();
}

// Helper: Format Bytes into human readable strings
function formatBytes(bytes) {
    if (bytes === 0 || bytes === null || bytes === undefined) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Helper: Format integers
function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return new Intl.NumberFormat().format(num);
}

// Fetch Exporters to populate filter dropdown
async function fetchExporterDropdown() {
    try {
        const res = await fetch('/api/exporters');
        if (!res.ok) throw new Error('Failed to fetch exporters list');
        const exporters = await res.json();
        
        const container = document.getElementById('filter-exporter-group');
        if (container) {
            container.innerHTML = '';
            exporters.forEach(ip => {
                const label = document.createElement('label');
                label.className = 'checkbox-label';
                label.innerHTML = `<input type="checkbox" name="exporter" value="${ip}" checked> ${ip}`;
                container.appendChild(label);
            });
            
            // Register change event listener on new checkboxes to update trigger label
            container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                cb.addEventListener('change', updateDropdownLabels);
            });
            updateDropdownLabels();
            
            // Apply exporter filters and fetch current stats
            refreshData();
        }
    } catch (err) {
        console.error('Error fetching exporters dropdown:', err);
    }
}

// Refresh active tab and KPI totals
function refreshData() {
    applyFiltersFromForm();
    fetchKPIs();
    if (state.activeTab === 'explorer') {
        fetchFlows();
    } else {
        fetchStats();
    }
}

// Fetch general totals for KPIs
async function fetchKPIs() {
    const params = new URLSearchParams({
        table: state.filters.table,
        time_range: state.filters.timeRange
    });
    if (state.filters.exporter) params.append('exporter', state.filters.exporter);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    try {
        const res = await fetch(`/api/stats?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to fetch KPI stats');
        const data = await res.json();
        
        els.kpiTotalFlows.innerText = formatNumber(data.total_flows);
        els.kpiTotalBytes.innerText = formatBytes(data.total_bytes);
        els.kpiTotalPackets.innerText = formatNumber(data.total_packets);
        els.kpiTotalExporters.innerText = formatNumber(data.top_exporters.length);
    } catch (err) {
        console.error('Error fetching KPIs:', err);
    }
}

// Build URL query parameters from current filter and sort state
function getFlowQueryParams() {
    const activeCols = getActiveColumns();
    const params = new URLSearchParams({
        table: state.filters.table,
        time_range: state.filters.timeRange,
        sort_by: state.sorting.by,
        sort_order: state.sorting.order,
        group_by: activeCols.join(',')
    });
    
    if (state.filters.exporter) params.append('exporter', state.filters.exporter);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);
    return params;
}

// Fetch flows list for table
async function fetchFlows() {
    const activeCols = getActiveColumns();
    const visibleColsCount = activeCols.length + 2; // +2 for packets and octets
    
    els.flowsTbody.innerHTML = `
        <tr>
            <td colspan="${visibleColsCount}" class="text-center text-muted py-5">
                <div class="spinner"></div>
                Loading flow records...
            </td>
        </tr>
    `;
    
    const params = getFlowQueryParams();
    params.append('limit', state.pagination.limit);
    params.append('offset', state.pagination.offset);
    
    try {
        const res = await fetch(`/api/flows?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to query flow records');
        const data = await res.json();
        
        state.records = data.records;
        state.pagination.total = data.total;
        
        renderFlowsTable();
        renderPagination();
    } catch (err) {
        els.flowsTbody.innerHTML = `
            <tr>
                <td colspan="${visibleColsCount}" class="text-center text-muted py-5">
                    <span style="color: var(--color-danger)">Error loading flows: ${err.message}</span>
                </td>
            </tr>
        `;
        console.error('Error fetching flows:', err);
    }
}

// Render the flows table rows
function renderFlowsTable() {
    const activeCols = getActiveColumns();
    const visibleColsCount = activeCols.length + 2;

    if (state.records.length === 0) {
        els.flowsTbody.innerHTML = `
            <tr>
                <td colspan="${visibleColsCount}" class="text-center text-muted py-5">
                    No matching flows found. Ensure collectors are active and receiving traffic.
                </td>
            </tr>
        `;
        els.flowRangeStart.innerText = '0';
        els.flowRangeEnd.innerText = '0';
        els.flowTotalFiltered.innerText = '0';
        return;
    }
    
    els.flowsTbody.innerHTML = '';
    state.records.forEach((r, idx) => {
        const tr = document.createElement('tr');
        tr.addEventListener('click', () => showFlowDetails(idx));
        
        // Table values mapping
        const badgeType = r.type === 'ipfix' ? 'badge-info' : (r.type === 'netflow9' ? 'badge-primary' : 'badge-warning');
        const typeLabel = r.type ? r.type.toUpperCase() : 'GROUPED';
        
        const timeFormatted = r.ts ? formatSqlTimestamp(r.ts) : 'Aggregated';
        const protocolText = r.proto_name || 'Aggregated';
        
        tr.innerHTML = `
            <td class="col-type"><span class="badge ${badgeType}">${typeLabel}</span></td>
            <td class="col-ts">${timeFormatted}</td>
            <td class="col-exporter">${r.exporter || '-'}</td>
            <td class="col-src">
                <strong>${r.src || '-'}</strong>
                ${r.src_domain ? `<div class="domain-subtext" title="${r.src_domain}">${r.src_domain}</div>` : ''}
            </td>
            <td class="col-sport"><span class="text-secondary">${r.sport !== null && r.sport !== undefined ? r.sport : '-'}</span></td>
            <td class="col-dst">
                <strong>${r.dst || '-'}</strong>
                ${r.dst_domain ? `<div class="domain-subtext" title="${r.dst_domain}">${r.dst_domain}</div>` : ''}
            </td>
            <td class="col-dport"><span class="text-secondary">${r.dport !== null && r.dport !== undefined ? r.dport : '-'}</span></td>
            <td class="col-proto"><span class="badge badge-success">${protocolText}</span></td>
            <td class="col-packets">${formatNumber(r.packets)}</td>
            <td class="col-octets"><strong>${formatBytes(r.octets)}</strong></td>
        `;
        els.flowsTbody.appendChild(tr);
    });
    
    // Apply layout toggles
    applyColumnVisibility();

    // Update pagination stats
    const start = state.pagination.offset + 1;
    const end = Math.min(state.pagination.offset + state.records.length, state.pagination.total);
    els.flowRangeStart.innerText = formatNumber(start);
    els.flowRangeEnd.innerText = formatNumber(end);
    els.flowTotalFiltered.innerText = formatNumber(state.pagination.total);
    
    // Create lucide icons inside rows
    lucide.createIcons();
}

// Render dynamic pagination buttons
function renderPagination() {
    const container = els.flowsPagination;
    container.innerHTML = '';
    
    const limit = state.pagination.limit;
    const offset = state.pagination.offset;
    const total = state.pagination.total;
    
    const totalPages = Math.ceil(total / limit);
    const currentPage = Math.floor(offset / limit) + 1;
    
    if (totalPages <= 1) return;
    
    // Prev Button
    const prevBtn = document.createElement('div');
    prevBtn.className = `pagination-btn ${currentPage === 1 ? 'disabled' : ''}`;
    prevBtn.innerHTML = '<i data-lucide="chevron-left" style="width: 14px; height: 14px"></i>';
    if (currentPage > 1) {
        prevBtn.addEventListener('click', () => {
            state.pagination.offset = (currentPage - 2) * limit;
            fetchFlows();
        });
    }
    container.appendChild(prevBtn);
    
    // Page Numbers (Show max 5 pages, with ellipses)
    let startPage = Math.max(1, currentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);
    if (endPage - startPage < 4) {
        startPage = Math.max(1, endPage - 4);
    }
    
    for (let p = startPage; p <= endPage; p++) {
        const btn = document.createElement('div');
        btn.className = `pagination-btn ${p === currentPage ? 'active' : ''}`;
        btn.innerText = p;
        btn.addEventListener('click', () => {
            if (p !== currentPage) {
                state.pagination.offset = (p - 1) * limit;
                fetchFlows();
            }
        });
        container.appendChild(btn);
    }
    
    // Next Button
    const nextBtn = document.createElement('div');
    nextBtn.className = `pagination-btn ${currentPage === totalPages ? 'disabled' : ''}`;
    nextBtn.innerHTML = '<i data-lucide="chevron-right" style="width: 14px; height: 14px"></i>';
    if (currentPage < totalPages) {
        nextBtn.addEventListener('click', () => {
            state.pagination.offset = currentPage * limit;
            fetchFlows();
        });
    }
    container.appendChild(nextBtn);
    
    // Re-create icons for pagination chevrons
    lucide.createIcons();
}

// Convert UTC DB Timestamp to local browser representation
function formatSqlTimestamp(tsString) {
    if (!tsString) return '';
    // Append Z to force browser to treat SQLite UTC string as UTC
    const dateStr = tsString.includes('Z') ? tsString : tsString.replace(' ', 'T') + 'Z';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return tsString;
    return d.toLocaleDateString() + ' ' + d.toTimeString().split(' ')[0];
}

// Show modal dialog containing complete details of clicked row
function showFlowDetails(idx) {
    const r = state.records[idx];
    if (!r) return;
    
    els.detailId.innerText = r.id || 'N/A (Grouped)';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : 'Aggregated';
    els.detailType.innerText = r.type ? r.type.toUpperCase() : 'GROUPED';
    els.detailType.className = `value badge ${r.type === 'ipfix' ? 'badge-info' : (r.type === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    els.detailExporter.innerText = r.exporter || 'Aggregated';
    els.detailSrc.innerText = r.src || 'Aggregated';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || 'Aggregated';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || 'Aggregated';
    els.detailOctets.innerText = `${formatNumber(r.octets)} bytes (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Render raw json formatted
    const raw = r.raw_details || {};
    els.detailRawJson.innerText = JSON.stringify(raw, null, 2);
    
    els.detailsModal.classList.add('active');
}

function closeModal() {
    els.detailsModal.classList.remove('active');
}

// Helper to format IP labels with domains in charts
function formatChartIPLabel(ip, domain) {
    if (!domain) return ip;
    const maxDomainLen = 18;
    const displayDomain = domain.length > maxDomainLen ? domain.substring(0, maxDomainLen) + '...' : domain;
    return `${ip} (${displayDomain})`;
}

// Fetch stats and render analytics charts
async function fetchStats() {
    const params = new URLSearchParams({
        table: state.filters.table,
        time_range: state.filters.timeRange
    });
    if (state.filters.exporter) params.append('exporter', state.filters.exporter);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    try {
        const res = await fetch(`/api/stats?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to fetch statistics');
        const data = await res.json();
        
        renderTimeChart(data.traffic_over_time);
        renderBarChart('chart-top-sources', 'Top Sources', data.top_sources.map(x => formatChartIPLabel(x.src, x.domain)), data.top_sources.map(x => x.bytes));
        renderBarChart('chart-top-destinations', 'Top Destinations', data.top_destinations.map(x => formatChartIPLabel(x.dst, x.domain)), data.top_destinations.map(x => x.bytes));
        renderBarChart('chart-top-src-ports', 'Top 10 Source Ports', data.top_source_ports.map(x => x.sport.toString()), data.top_source_ports.map(x => x.bytes));
        renderBarChart('chart-top-dst-ports', 'Top 10 Destination Ports', data.top_destination_ports.map(x => x.dport.toString()), data.top_destination_ports.map(x => x.bytes));
        renderDoughnutChart('chart-protocols', data.protocols.map(x => x.name), data.protocols.map(x => x.count));
        renderDoughnutChart('chart-exporters', data.top_exporters.map(x => x.exporter), data.top_exporters.map(x => x.flows));
        
    } catch (err) {
        console.error('Error fetching stats:', err);
    }
}

// Chart renderers
function renderTimeChart(timeData) {
    const canvasId = 'chart-traffic-time';
    destroyChart(canvasId);
    
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    const labels = timeData.map(x => {
        // format label according to time bin
        const bin = x.time_bin;
        if (!bin) return '';
        // E.g. "2026-07-03 14:00:00" -> "14:00"
        if (bin.length > 13) return bin.substring(11, 16);
        return bin;
    });
    
    const bytesData = timeData.map(x => x.bytes);
    const packetsData = timeData.map(x => x.packets);
    
    state.charts[canvasId] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Traffic Volume (Bytes)',
                    data: bytesData,
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    yAxisID: 'y-bytes',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2
                },
                {
                    label: 'Packets',
                    data: packetsData,
                    borderColor: '#10b981',
                    backgroundColor: 'transparent',
                    yAxisID: 'y-packets',
                    fill: false,
                    tension: 0.3,
                    borderWidth: 2,
                    borderDash: [5, 5]
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: {
                    labels: { color: '#9ca3af' }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.datasetIndex === 0) {
                                label += formatBytes(context.parsed.y);
                            } else {
                                label += formatNumber(context.parsed.y);
                            }
                            return label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#9ca3af' }
                },
                'y-bytes': {
                    type: 'linear',
                    position: 'left',
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: {
                        color: '#9ca3af',
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                },
                'y-packets': {
                    type: 'linear',
                    position: 'right',
                    grid: { drawOnChartArea: false }, // avoid grid overlap
                    ticks: {
                        color: '#9ca3af',
                        callback: function(value) {
                            return formatNumber(value);
                        }
                    }
                }
            }
        }
    });
}

function renderBarChart(canvasId, title, labels, data) {
    destroyChart(canvasId);
    
    const ctx = document.getElementById(canvasId).getContext('2d');
    state.charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Volume (Bytes)',
                data: data,
                backgroundColor: 'rgba(99, 102, 241, 0.75)',
                borderColor: '#6366f1',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return 'Volume: ' + formatBytes(context.parsed.y);
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#9ca3af' }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: {
                        color: '#9ca3af',
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });
}

function renderDoughnutChart(canvasId, labels, data) {
    destroyChart(canvasId);
    if (labels.length === 0) return; // avoid empty doughnut bug
    
    const ctx = document.getElementById(canvasId).getContext('2d');
    state.charts[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#6366f1', // Indigo
                    '#10b981', // Emerald
                    '#0ea5e9', // Sky Blue
                    '#f59e0b', // Amber
                    '#ef4444', // Rose Red
                    '#8b5cf6', // Purple
                    '#ec4899', // Pink
                ],
                borderWidth: 1,
                borderColor: '#111827'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#9ca3af',
                        font: { size: 11 }
                    }
                }
            }
        }
    });
}

// Clean up chart instance if it exists to allow rendering new data without bugs
function destroyChart(canvasId) {
    if (state.charts[canvasId]) {
        state.charts[canvasId].destroy();
        delete state.charts[canvasId];
    }
}

// Setup Header Sorting click listeners
function setupHeaderSorting() {
    const headers = document.querySelectorAll('th.sortable');
    headers.forEach(th => {
        th.addEventListener('click', () => {
            const sortBy = th.getAttribute('data-sort');
            if (state.sorting.by === sortBy) {
                // Toggle order
                state.sorting.order = state.sorting.order === 'asc' ? 'desc' : 'asc';
            } else {
                state.sorting.by = sortBy;
                state.sorting.order = 'desc'; // Default to desc for new fields
            }
            updateHeaderSortIcons();
            state.pagination.offset = 0; // Reset pagination
            fetchFlows();
        });
    });
}

// Update header sorting icons state
function updateHeaderSortIcons() {
    const headers = document.querySelectorAll('th.sortable');
    headers.forEach(th => {
        const sortBy = th.getAttribute('data-sort');
        const icon = th.querySelector('.sort-icon');
        if (icon) {
            if (sortBy === state.sorting.by) {
                th.classList.add('sort-active');
                if (state.sorting.order === 'asc') {
                    icon.setAttribute('data-lucide', 'chevron-up');
                } else {
                    icon.setAttribute('data-lucide', 'chevron-down');
                }
            } else {
                th.classList.remove('sort-active');
                icon.setAttribute('data-lucide', 'chevrons-up-down');
            }
        }
    });
    // Re-initialize Lucide Icons so they re-render the new icon types
    lucide.createIcons();
}

// Read checkbox-group to build comma-separated protocol string
function getSelectedProtocols() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#filter-proto-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    return checked.join(',');
}

// Read checked columns visibility list
function getActiveColumns() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    return checked;
}

// Setup Column display toggles change listener
function setupColumnToggles() {
    const toggles = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    toggles.forEach(toggle => {
        toggle.addEventListener('change', () => {
            state.pagination.offset = 0; // Reset pagination
            fetchFlows();
        });
    });
}

// Apply table columns visibility hide/show classes dynamically
function applyColumnVisibility() {
    const toggles = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    toggles.forEach(toggle => {
        const colName = toggle.value;
        const visible = toggle.checked;
        const cells = document.querySelectorAll(`.col-${colName}`);
        cells.forEach(cell => {
            cell.style.display = visible ? '' : 'none';
        });
    });
    
    // Sync loading/empty message colspans
    const activeCols = getActiveColumns();
    const visibleCount = activeCols.length + 2; // Add Packets and Bytes
    const colspans = document.querySelectorAll('#flows-tbody td[colspan]');
    colspans.forEach(cell => {
        cell.setAttribute('colspan', visibleCount);
    });
}

// Toggle custom dropdowns open state
function setupDropdowns() {
    const dropdowns = document.querySelectorAll('.custom-dropdown');
    
    dropdowns.forEach(dd => {
        const trigger = dd.querySelector('.dropdown-trigger');
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            
            // Close other dropdowns
            dropdowns.forEach(other => {
                if (other !== dd) {
                    other.classList.remove('open');
                }
            });
            
            dd.classList.toggle('open');
        });
        
        // Prevent clicks inside panel from closing dropdown
        const panel = dd.querySelector('.dropdown-menu-panel');
        panel.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    });
    
    // Clicking outside closes all dropdowns
    document.addEventListener('click', () => {
        dropdowns.forEach(dd => {
            dd.classList.remove('open');
        });
    });
    
    // Register update listeners on checkboxes
    const checkboxes = document.querySelectorAll('.custom-dropdown input[type="checkbox"]');
    checkboxes.forEach(cb => {
        cb.addEventListener('change', updateDropdownLabels);
    });
    
    // Initial label render
    updateDropdownLabels();
}

// Sync label texts on dropdown triggers
function updateDropdownLabels() {
    // Update Protocols Label
    const checkedProtos = [];
    const protoCheckboxes = document.querySelectorAll('#filter-proto-group input[type="checkbox"]');
    protoCheckboxes.forEach(cb => {
        if (cb.checked) checkedProtos.push(cb.value);
    });
    const labelProto = document.getElementById('label-proto');
    if (labelProto) {
        if (checkedProtos.length === 0) {
            labelProto.innerText = 'None';
        } else if (checkedProtos.length === protoCheckboxes.length) {
            labelProto.innerText = 'All Protocols';
        } else {
            labelProto.innerText = checkedProtos.join(', ');
        }
    }
    
    // Update Data Source Label
    const checkedTables = [];
    const tableCheckboxes = document.querySelectorAll('#filter-table-group input[type="checkbox"]');
    tableCheckboxes.forEach(cb => {
        if (cb.checked) {
            checkedTables.push(cb.parentNode.textContent.trim());
        }
    });
    const labelTable = document.getElementById('label-table');
    if (labelTable) {
        if (checkedTables.length === 0) {
            labelTable.innerText = 'None';
        } else if (checkedTables.length === tableCheckboxes.length) {
            labelTable.innerText = 'All Data Sources';
        } else {
            labelTable.innerText = checkedTables.join(', ');
        }
    }

    // Update Exporter IP Label
    const checkedExporters = [];
    const exporterCheckboxes = document.querySelectorAll('#filter-exporter-group input[type="checkbox"]');
    exporterCheckboxes.forEach(cb => {
        if (cb.checked) {
            checkedExporters.push(cb.value);
        }
    });
    const labelExporter = document.getElementById('label-exporter');
    if (labelExporter) {
        if (checkedExporters.length === 0) {
            labelExporter.innerText = 'None';
        } else if (checkedExporters.length === exporterCheckboxes.length) {
            labelExporter.innerText = 'All Exporters';
        } else {
            labelExporter.innerText = checkedExporters.length > 2 
                ? `${checkedExporters.length} Exporters` 
                : checkedExporters.join(', ');
        }
    }
    
    // Update Columns Label
    const checkedCols = [];
    const colCheckboxes = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    colCheckboxes.forEach(cb => {
        if (cb.checked) {
            checkedCols.push(cb.parentNode.textContent.trim());
        }
    });
    const labelCols = document.getElementById('label-columns');
    if (labelCols) {
        if (checkedCols.length === 0) {
            labelCols.innerText = 'None';
        } else if (checkedCols.length === colCheckboxes.length) {
            labelCols.innerText = 'All Columns';
        } else {
            labelCols.innerText = `${checkedCols.length} Columns`;
        }
    }
}

function getSelectedTables() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#filter-table-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    return checked.join(',');
}

function getSelectedExporters() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#filter-exporter-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    return checked.join(',');
}

// Convert local datetime-local string input value to UTC SQLite format YYYY-MM-DD HH:MM:SS
function toUtcTimestamp(localStr) {
    if (!localStr) return '';
    try {
        const d = new Date(localStr);
        if (isNaN(d.getTime())) return '';
        return d.toISOString().replace('T', ' ').substring(0, 19);
    } catch (e) {
        return '';
    }
}

// Execute Data Cleanup API POST Request
async function executeCleanup() {
    const beforeVal = els.cleanupBeforeDate.value;
    if (!beforeVal) {
        showCleanupStatus('Please select a date and time.', 'error');
        return;
    }
    
    const utcDate = toUtcTimestamp(beforeVal);
    if (!utcDate) {
        showCleanupStatus('Invalid date selected.', 'error');
        return;
    }
    
    if (!confirm(`Are you sure you want to delete all NetFlow data before ${utcDate} (UTC)? This action cannot be undone.`)) {
        return;
    }
    
    showCleanupStatus('Executing cleanup...', 'info');
    els.btnExecuteCleanup.disabled = true;
    
    try {
        const response = await fetch(`/api/flows/delete?before=${encodeURIComponent(utcDate)}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        if (response.ok) {
            showCleanupStatus(data.message || 'Cleanup successfully initiated.', 'success');
            els.cleanupBeforeDate.value = ''; // Reset input
        } else {
            showCleanupStatus(data.detail || 'Failed to initiate cleanup.', 'error');
        }
    } catch (err) {
        showCleanupStatus(`Network error: ${err.message}`, 'error');
    } finally {
        els.btnExecuteCleanup.disabled = false;
    }
}

function showCleanupStatus(message, type) {
    const el = els.cleanupStatusMessage;
    el.style.display = 'block';
    el.innerText = message;
    
    // Reset background and borders
    el.style.backgroundColor = '';
    el.style.color = '';
    el.style.border = '';
    
    if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else { // info
        el.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
        el.style.color = '#818cf8';
        el.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    }
}
