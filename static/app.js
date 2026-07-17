// app.js

// State management
let state = {
    activeTab: 'anomalies', // 'explorer', 'analytics' or 'anomalies'
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
    auditPagination: {
        limit: 50,
        offset: 0,
        total: 0
    },
    anomaliesPagination: {
        limit: 50,
        offset: 0,
        total: 0
    },
    ipAliasesPagination: {
        limit: 25,
        offset: 0,
        total: 0,
        search: ''
    },
    auditFilters: {
        src: '',
        dst: '',
        port: '',
        flag: ''
    },
    anomaliesFilters: {
        src: '',
        dst: '',
        port: '',
        flag: ''
    },
    sorting: {
        by: 'ts',
        order: 'desc'
    },
    auditSorting: {
        by: 'match_ts',
        order: 'desc'
    },
    records: [], // Cache for current page records
    charts: {}   // Store Chart.js instances
};

// UI Elements
const els = {
    btnTabExplorer: document.getElementById('btn-tab-explorer'),
    btnTabAnalytics: document.getElementById('btn-tab-analytics'),
    btnTabAnomalies: document.getElementById('btn-tab-anomalies'),
    btnTabSettingsTrigger: document.getElementById('btn-tab-settings-trigger'),
    btnTabManagement: document.getElementById('btn-tab-management'),
    btnTabAliases: document.getElementById('btn-tab-aliases'),
    btnTabAudit: document.getElementById('btn-tab-audit'),
    viewExplorer: document.getElementById('view-explorer'),
    viewAnalytics: document.getElementById('view-analytics'),
    viewAnomalies: document.getElementById('view-anomalies'),
    viewDataManagement: document.getElementById('view-data-management'),
    viewAliasManager: document.getElementById('view-alias-manager'),
    viewAudit: document.getElementById('view-audit'),
    cleanupBeforeDate: document.getElementById('cleanup-before-date'),
    btnExecuteCleanup: document.getElementById('btn-execute-cleanup'),
    cleanupStatusMessage: document.getElementById('cleanup-status-message'),
    
    // Auditing Elements
    btnTriggerAudit: document.getElementById('btn-trigger-audit'),
    auditLastRunTime: document.getElementById('audit-last-run-time'),
    auditNextRunTime: document.getElementById('audit-next-run-time'),
    auditLastRunStatus: document.getElementById('audit-last-run-status'),
    auditLastRunMatches: document.getElementById('audit-last-run-matches'),
    auditLastRunMessage: document.getElementById('audit-last-run-message'),
    auditTriggerStatus: document.getElementById('audit-trigger-status'),
    auditTriggerModal: document.getElementById('audit-trigger-modal'),
    btnCloseTriggerModal: document.getElementById('btn-close-trigger-modal'),
    btnCancelTriggerAudit: document.getElementById('btn-cancel-trigger-audit'),
    btnConfirmTriggerAudit: document.getElementById('btn-confirm-trigger-audit'),
    auditOptionLastRunLabel: document.getElementById('audit-option-last-run-label'),
    auditCustomStartTime: document.getElementById('audit-custom-start-time'),
    auditRuleForm: document.getElementById('audit-rule-form'),
    auditInputIp: document.getElementById('audit-input-ip'),
    auditInputPort: document.getElementById('audit-input-port'),
    auditRuleStatusMessage: document.getElementById('audit-rule-status-message'),
    auditRulesTbody: document.getElementById('audit-rules-tbody'),
    btnExportRules: document.getElementById('btn-export-rules'),
    btnImportRules: document.getElementById('btn-import-rules'),
    inputImportRules: document.getElementById('input-import-rules'),
    btnClearRules: document.getElementById('btn-clear-rules'),
    
    // Audit Search / Table / Pagination
    auditPageSize: document.getElementById('audit-page-size'),
    btnClearAuditMatches: document.getElementById('btn-clear-audit-matches'),
    btnExportAuditMatches: document.getElementById('btn-export-audit-matches'),
    auditTotalFiltered: document.getElementById('audit-total-filtered'),
    auditPagination: document.getElementById('audit-pagination'),
    auditMatchesTbody: document.getElementById('audit-matches-tbody'),
    filterAuditSrc: document.getElementById('filter-audit-src'),
    filterAuditDst: document.getElementById('filter-audit-dst'),
    filterAuditPort: document.getElementById('filter-audit-port'),
    filterAuditFlag: document.getElementById('filter-audit-flag'),
    btnApplyAuditSearch: document.getElementById('btn-apply-audit-search'),
    btnResetAuditSearch: document.getElementById('btn-reset-audit-search'),

    // Anomalies Report elements
    anomaliesPageSize: document.getElementById('anomalies-page-size'),
    btnExportAnomalies: document.getElementById('btn-export-anomalies'),
    anomaliesTotalFiltered: document.getElementById('anomalies-total-filtered'),
    anomaliesPagination: document.getElementById('anomalies-pagination'),
    anomaliesTbody: document.getElementById('anomalies-tbody'),
    filterAnomaliesSrc: document.getElementById('filter-anomalies-src'),
    filterAnomaliesDst: document.getElementById('filter-anomalies-dst'),
    filterAnomaliesPort: document.getElementById('filter-anomalies-port'),
    filterAnomaliesFlag: document.getElementById('filter-anomalies-flag'),
    btnApplyAnomaliesSearch: document.getElementById('btn-apply-anomalies-search'),
    btnResetAnomaliesSearch: document.getElementById('btn-reset-anomalies-search'),
    
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
    setupAuditHeaderSorting();
    updateAuditHeaderSortIcons();
    setupColumnToggles();
    setupDropdowns();
    fetchExporterDropdown();
    fetchPortAliases();
    fetchIpAliases();
    switchTab('anomalies');
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

    if (els.btnTabAnomalies) {
        els.btnTabAnomalies.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('anomalies');
        });
    }

    if (els.btnTabSettingsTrigger) {
        els.btnTabSettingsTrigger.addEventListener('click', (e) => {
            e.preventDefault();
            const submenu = document.querySelector('#menu-settings .submenu');
            const chevron = els.btnTabSettingsTrigger.querySelector('.chevron-icon');
            if (submenu) {
                const isOpen = submenu.style.display === 'flex';
                submenu.style.display = isOpen ? 'none' : 'flex';
                if (chevron) {
                    chevron.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(-180deg)';
                }
            }
        });
    }

    if (els.btnTabManagement) {
        els.btnTabManagement.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('data-management');
        });
    }

    if (els.btnTabAliases) {
        els.btnTabAliases.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('aliases');
        });
    }

    if (els.btnTabAudit) {
        els.btnTabAudit.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('audit');
        });
    }

    if (els.auditRuleForm) {
        els.auditRuleForm.addEventListener('submit', (e) => {
            e.preventDefault();
            submitAuditRule();
        });
    }

    if (els.btnTriggerAudit) {
        els.btnTriggerAudit.addEventListener('click', () => {
            if (els.auditTriggerModal) {
                // Populate last run time label in the modal
                const lastRunText = els.auditLastRunTime ? els.auditLastRunTime.innerText : '-';
                if (els.auditOptionLastRunLabel) {
                    els.auditOptionLastRunLabel.innerText = `上次時間: ${lastRunText}`;
                }
                
                // Reset radios to "last-run"
                const defaultRadio = document.querySelector('input[name="audit-range-option"][value="last-run"]');
                if (defaultRadio) defaultRadio.checked = true;
                
                // Hide custom start time input initially
                if (els.auditCustomStartTime) {
                    els.auditCustomStartTime.style.display = 'none';
                    els.auditCustomStartTime.value = '';
                }
                
                // Show modal
                els.auditTriggerModal.classList.add('active');
            }
        });
    }

    // Modal toggle radio inputs visibility
    const radioOptions = document.querySelectorAll('input[name="audit-range-option"]');
    radioOptions.forEach(radio => {
        radio.addEventListener('change', () => {
            if (els.auditCustomStartTime) {
                els.auditCustomStartTime.style.display = (radio.value === 'custom') ? 'block' : 'none';
            }
        });
    });

    // Close trigger modal triggers
    const closeTriggerModal = () => {
        if (els.auditTriggerModal) {
            els.auditTriggerModal.classList.remove('active');
        }
    };
    if (els.btnCloseTriggerModal) {
        els.btnCloseTriggerModal.addEventListener('click', closeTriggerModal);
    }
    if (els.btnCancelTriggerAudit) {
        els.btnCancelTriggerAudit.addEventListener('click', closeTriggerModal);
    }

    // Confirm trigger audit
    if (els.btnConfirmTriggerAudit) {
        els.btnConfirmTriggerAudit.addEventListener('click', () => {
            closeTriggerModal();
            
            const selectedOption = document.querySelector('input[name="audit-range-option"]:checked')?.value || 'last-run';
            let startTime = null;
            
            if (selectedOption === 'all-time') {
                startTime = '1970-01-01 00:00:00';
            } else if (selectedOption === 'custom') {
                if (!els.auditCustomStartTime.value) {
                    alert('請選擇自訂的開始時間！');
                    return;
                }
                startTime = els.auditCustomStartTime.value; // e.g. "2026-07-09T10:30"
            }
            
            triggerManualAudit(startTime);
        });
    }

    if (els.btnClearAuditMatches) {
        els.btnClearAuditMatches.addEventListener('click', () => {
            clearAuditMatches();
        });
    }
    
    if (els.auditPageSize) {
        els.auditPageSize.addEventListener('change', () => {
            state.auditPagination.limit = parseInt(els.auditPageSize.value);
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        });
    }

    if (els.btnApplyAuditSearch) {
        els.btnApplyAuditSearch.addEventListener('click', () => {
            state.auditFilters.src = els.filterAuditSrc.value.trim();
            state.auditFilters.dst = els.filterAuditDst.value.trim();
            state.auditFilters.port = els.filterAuditPort.value.trim();
            state.auditFilters.flag = els.filterAuditFlag.value;
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        });
    }

    if (els.btnResetAuditSearch) {
        els.btnResetAuditSearch.addEventListener('click', () => {
            els.filterAuditSrc.value = '';
            els.filterAuditDst.value = '';
            els.filterAuditPort.value = '';
            els.filterAuditFlag.value = '';
            state.auditFilters.src = '';
            state.auditFilters.dst = '';
            state.auditFilters.port = '';
            state.auditFilters.flag = '';
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        });
    }

    if (els.btnExportAuditMatches) {
        els.btnExportAuditMatches.addEventListener('click', () => {
            let url = `/api/audit/matches/export?`;
            const params = [];
            if (state.auditFilters.src) params.push(`src=${encodeURIComponent(state.auditFilters.src)}`);
            if (state.auditFilters.dst) params.push(`dst=${encodeURIComponent(state.auditFilters.dst)}`);
            if (state.auditFilters.port) params.push(`port=${encodeURIComponent(state.auditFilters.port)}`);
            if (state.auditFilters.flag) params.push(`flag=${encodeURIComponent(state.auditFilters.flag)}`);
            window.open(url + params.join('&'), '_blank');
        });
    }

    if (els.anomaliesPageSize) {
        els.anomaliesPageSize.addEventListener('change', () => {
            state.anomaliesPagination.limit = parseInt(els.anomaliesPageSize.value);
            state.anomaliesPagination.offset = 0;
            fetchAnomalousReport();
        });
    }

    if (els.btnApplyAnomaliesSearch) {
        els.btnApplyAnomaliesSearch.addEventListener('click', () => {
            state.anomaliesFilters.src = els.filterAnomaliesSrc.value.trim();
            state.anomaliesFilters.dst = els.filterAnomaliesDst.value.trim();
            state.anomaliesFilters.port = els.filterAnomaliesPort.value.trim();
            state.anomaliesFilters.flag = els.filterAnomaliesFlag.value;
            state.anomaliesPagination.offset = 0;
            fetchAnomalousReport();
        });
    }

    if (els.btnResetAnomaliesSearch) {
        els.btnResetAnomaliesSearch.addEventListener('click', () => {
            els.filterAnomaliesSrc.value = '';
            els.filterAnomaliesDst.value = '';
            els.filterAnomaliesPort.value = '';
            els.filterAnomaliesFlag.value = '';
            state.anomaliesFilters.src = '';
            state.anomaliesFilters.dst = '';
            state.anomaliesFilters.port = '';
            state.anomaliesFilters.flag = '';
            state.anomaliesPagination.offset = 0;
            fetchAnomalousReport();
        });
    }

    if (els.btnExportAnomalies) {
        els.btnExportAnomalies.addEventListener('click', () => {
            let url = `/api/audit/matches/export?`;
            const params = [];
            if (state.anomaliesFilters.src) params.push(`src=${encodeURIComponent(state.anomaliesFilters.src)}`);
            if (state.anomaliesFilters.dst) params.push(`dst=${encodeURIComponent(state.anomaliesFilters.dst)}`);
            if (state.anomaliesFilters.port) params.push(`port=${encodeURIComponent(state.anomaliesFilters.port)}`);
            if (state.anomaliesFilters.flag) params.push(`flag=${encodeURIComponent(state.anomaliesFilters.flag)}`);
            window.open(url + params.join('&'), '_blank');
        });
    }

    els.btnExecuteCleanup.addEventListener('click', () => {
        executeCleanup();
    });

    if (els.btnExportRules) {
        els.btnExportRules.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/audit/rules/export');
                if (!res.ok) throw new Error('Export request failed');
                const data = await res.json();
                
                // Trigger download
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'netflow_audit_rules_backup.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showAuditRuleStatus('Audit rules backup file downloaded successfully', 'success');
            } catch (err) {
                showAuditRuleStatus(`Export failed: ${err.message}`, 'error');
            }
        });
    }

    if (els.btnImportRules && els.inputImportRules) {
        els.btnImportRules.addEventListener('click', () => {
            els.inputImportRules.click();
        });

        els.inputImportRules.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (event) => {
                try {
                    const payload = JSON.parse(event.target.result);
                    if (!Array.isArray(payload)) {
                        throw new Error('Invalid backup file format (expected a JSON array of rules)');
                    }

                    const res = await fetch('/api/audit/rules/import', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    
                    if (res.ok) {
                        showAuditRuleStatus(data.message || 'Import successful', 'success');
                        fetchAuditRules(); // Reload rule table
                    } else {
                        showAuditRuleStatus(data.detail || 'Import failed', 'error');
                    }
                } catch (err) {
                    showAuditRuleStatus(`Import parse error: ${err.message}`, 'error');
                }
                // Reset file input value to allow importing the same file again
                els.inputImportRules.value = '';
            };
            reader.readAsText(file);
        });
    }

    if (els.btnClearRules) {
        els.btnClearRules.addEventListener('click', async () => {
            if (!confirm('您確定要清除所有的流量盤查規則嗎？此動作將無法復原。')) {
                return;
            }
            try {
                const res = await fetch('/api/audit/rules', { method: 'DELETE' });
                const data = await res.json();
                if (res.ok) {
                    showAuditRuleStatus('所有盤查規則已成功清除！', 'success');
                    fetchAuditRules(); // Reload rules list
                } else {
                    showAuditRuleStatus(data.detail || '清除失敗', 'error');
                }
            } catch (err) {
                showAuditRuleStatus(`清除錯誤: ${err.message}`, 'error');
            }
        });
    }
    
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
    
    // Port Alias form listener
    const formPortAlias = document.getElementById('form-port-alias');
    if (formPortAlias) {
        formPortAlias.addEventListener('submit', handleSavePortAlias);
    }

    // IP Alias form listener
    const formIpAlias = document.getElementById('form-ip-alias');
    if (formIpAlias) {
        formIpAlias.addEventListener('submit', handleSaveIpAlias);
    }

    // Segmented toggle button listeners for Alias Manager
    const btnToggleIp = document.getElementById('btn-toggle-ip');
    const btnTogglePort = document.getElementById('btn-toggle-port');
    const containerIpAlias = document.getElementById('container-ip-alias');
    const containerPortAlias = document.getElementById('container-port-alias');

    if (btnToggleIp && btnTogglePort && containerIpAlias && containerPortAlias) {
        btnToggleIp.addEventListener('click', () => {
            btnToggleIp.classList.add('active');
            btnTogglePort.classList.remove('active');
            containerIpAlias.style.display = 'block';
            containerPortAlias.style.display = 'none';
        });

        btnTogglePort.addEventListener('click', () => {
            btnTogglePort.classList.add('active');
            btnToggleIp.classList.remove('active');
            containerPortAlias.style.display = 'block';
            containerIpAlias.style.display = 'none';
        });
    }

    // Export / Import Backup bindings
    const btnExportAliases = document.getElementById('btn-export-aliases');
    const btnImportAliases = document.getElementById('btn-import-aliases');
    const inputImportAliases = document.getElementById('input-import-aliases');

    if (btnExportAliases) {
        btnExportAliases.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/aliases/export');
                if (!res.ok) throw new Error('Export request failed');
                const data = await res.json();
                
                // Trigger download
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'netflow_aliases_backup.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showIpAliasStatus('Aliases backup file downloaded successfully', 'success');
            } catch (err) {
                showIpAliasStatus(`Export failed: ${err.message}`, 'error');
            }
        });
    }

    if (btnImportAliases && inputImportAliases) {
        btnImportAliases.addEventListener('click', () => {
            inputImportAliases.click();
        });

        inputImportAliases.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (event) => {
                try {
                    const payload = JSON.parse(event.target.result);
                    if (!payload.ip_aliases || !payload.port_aliases) {
                        throw new Error('Invalid backup file format (missing ip_aliases or port_aliases)');
                    }

                    const res = await fetch('/api/aliases/import', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(payload)
                    });

                    if (!res.ok) throw new Error('API import request failed');
                    const result = await res.json();
                    
                    showIpAliasStatus(result.message, 'success');
                    fetchIpAliases();
                    fetchPortAliases();
                    fetchFlows();
                } catch (err) {
                    showIpAliasStatus(`Import failed: ${err.message}`, 'error');
                } finally {
                    // Reset input
                    inputImportAliases.value = '';
                }
            };
            reader.readAsText(file);
        });
    }

    const btnClearAliases = document.getElementById('btn-clear-aliases');
    if (btnClearAliases) {
        btnClearAliases.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to delete ALL custom IP and Port aliases? This cannot be undone.')) return;
            
            try {
                const res = await fetch('/api/aliases/clear', { method: 'POST' });
                if (!res.ok) throw new Error('Clear request failed');
                const result = await res.json();
                
                showIpAliasStatus(result.message, 'success');
                showPortAliasStatus(result.message, 'success');
                
                fetchIpAliases();
                fetchPortAliases();
                fetchFlows();
            } catch (err) {
                showIpAliasStatus(`Clear failed: ${err.message}`, 'error');
            }
        });
    }

    // IP aliases search
    const searchInput = document.getElementById('input-search-ip-aliases');
    if (searchInput) {
        let timeout = null;
        searchInput.addEventListener('input', () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                state.ipAliasesPagination.search = searchInput.value;
                state.ipAliasesPagination.offset = 0;
                fetchIpAliases();
            }, 300);
        });
    }

    // IP aliases pagination clicks
    const btnIpPrev = document.getElementById('btn-ip-aliases-prev');
    if (btnIpPrev) {
        btnIpPrev.addEventListener('click', () => {
            state.ipAliasesPagination.offset = Math.max(0, state.ipAliasesPagination.offset - state.ipAliasesPagination.limit);
            fetchIpAliases();
        });
    }

    const btnIpNext = document.getElementById('btn-ip-aliases-next');
    if (btnIpNext) {
        btnIpNext.addEventListener('click', () => {
            state.ipAliasesPagination.offset += state.ipAliasesPagination.limit;
            fetchIpAliases();
        });
    }
}

// Tab Switching logic
function switchTab(tabName) {
    state.activeTab = tabName;
    
    // Hide filter card if settings/report tabs are active
    const isSettingsTab = ['data-management', 'aliases', 'audit', 'anomalies'].includes(tabName);
    const filterCard = document.querySelector('.filter-card');
    if (filterCard) {
        filterCard.style.display = isSettingsTab ? 'none' : 'block';
    }
    
    // Show/hide top header and KPI grid (only needed for Flow Explorer and Traffic Analytics)
    const showHeaderKpi = ['explorer', 'analytics'].includes(tabName);
    const topHeader = document.querySelector('.top-header');
    const kpiGrid = document.querySelector('.kpi-grid');
    if (topHeader) {
        topHeader.style.display = showHeaderKpi ? 'flex' : 'none';
    }
    if (kpiGrid) {
        kpiGrid.style.display = showHeaderKpi ? 'grid' : 'none';
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
    if (els.btnTabAnomalies) els.btnTabAnomalies.classList.remove('active');
    if (els.btnTabSettingsTrigger) els.btnTabSettingsTrigger.classList.remove('active');
    if (els.btnTabManagement) els.btnTabManagement.classList.remove('active');
    if (els.btnTabAliases) els.btnTabAliases.classList.remove('active');
    if (els.btnTabAudit) els.btnTabAudit.classList.remove('active');
    
    els.viewExplorer.classList.remove('active');
    els.viewAnalytics.classList.remove('active');
    if (els.viewAnomalies) els.viewAnomalies.classList.remove('active');
    if (els.viewDataManagement) els.viewDataManagement.classList.remove('active');
    if (els.viewAliasManager) els.viewAliasManager.classList.remove('active');
    if (els.viewAudit) els.viewAudit.classList.remove('active');
    
    // Activate selected tab and view
    if (tabName === 'explorer') {
        els.btnTabExplorer.classList.add('active');
        els.viewExplorer.classList.add('active');
        refreshData();
    } else if (tabName === 'analytics') {
        els.btnTabAnalytics.classList.add('active');
        els.viewAnalytics.classList.add('active');
        refreshData();
    } else if (tabName === 'anomalies') {
        if (els.btnTabAnomalies) els.btnTabAnomalies.classList.add('active');
        if (els.viewAnomalies) els.viewAnomalies.classList.add('active');
        fetchAnomalousReport();
    } else {
        // Settings sub-tabs routing
        let activeBtn = null;
        let activeView = null;
        
        if (tabName === 'data-management') {
            activeBtn = els.btnTabManagement;
            activeView = els.viewDataManagement;
        } else if (tabName === 'aliases') {
            activeBtn = els.btnTabAliases;
            activeView = els.viewAliasManager;
        } else if (tabName === 'audit') {
            activeBtn = els.btnTabAudit;
            activeView = els.viewAudit;
            fetchAuditRules();
            fetchAuditStatus();
            fetchAuditMatches();
        }
        
        if (activeBtn) activeBtn.classList.add('active');
        if (activeView) activeView.classList.add('active');
        
        // Auto-expand Settings submenu if collapsed
        const submenu = document.querySelector('#menu-settings .submenu');
        const chevron = document.querySelector('#btn-tab-settings-trigger .chevron-icon');
        if (submenu) {
            submenu.style.display = 'flex';
            if (chevron) {
                chevron.style.transform = 'rotate(-180deg)';
            }
        }
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
            <td class="col-sport">
                <span class="text-secondary">${r.sport !== null && r.sport !== undefined ? r.sport : '-'}</span>
                ${r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : ''}
            </td>
            <td class="col-dst">
                <strong>${r.dst || '-'}</strong>
                ${r.dst_domain ? `<div class="domain-subtext" title="${r.dst_domain}">${r.dst_domain}</div>` : ''}
            </td>
            <td class="col-dport">
                <span class="text-secondary">${r.dport !== null && r.dport !== undefined ? r.dport : '-'}</span>
                ${r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : ''}
            </td>
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
        renderBarChart('chart-top-src-ports', 'Top 10 Source Ports', data.top_source_ports.map(x => x.sport.toString() + (x.port_name ? ` (${x.port_name})` : '')), data.top_source_ports.map(x => x.bytes));
        renderBarChart('chart-top-dst-ports', 'Top 10 Destination Ports', data.top_destination_ports.map(x => x.dport.toString() + (x.port_name ? ` (${x.port_name})` : '')), data.top_destination_ports.map(x => x.bytes));
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
    const headers = document.querySelectorAll('#flows-table th.sortable');
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
    const headers = document.querySelectorAll('#flows-table th.sortable');
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

// Setup Audit Tables Header Sorting click listeners
function setupAuditHeaderSorting() {
    const headers = document.querySelectorAll('#anomalies-table th.sortable, #audit-matches-table th.sortable');
    headers.forEach(th => {
        th.addEventListener('click', () => {
            const sortBy = th.getAttribute('data-sort');
            if (state.auditSorting.by === sortBy) {
                state.auditSorting.order = state.auditSorting.order === 'asc' ? 'desc' : 'asc';
            } else {
                state.auditSorting.by = sortBy;
                state.auditSorting.order = 'desc';
            }
            updateAuditHeaderSortIcons();
            
            // Reset pagination offsets
            state.auditPagination.offset = 0;
            state.anomaliesPagination.offset = 0;
            
            // Fetch matches & anomalies report
            fetchAuditMatches();
            fetchAnomalousReport();
        });
    });
}

// Update audit tables header sorting icons state
function updateAuditHeaderSortIcons() {
    const headers = document.querySelectorAll('#anomalies-table th.sortable, #audit-matches-table th.sortable');
    headers.forEach(th => {
        const sortBy = th.getAttribute('data-sort');
        const icon = th.querySelector('.sort-icon');
        if (icon) {
            if (sortBy === state.auditSorting.by) {
                th.classList.add('sort-active');
                if (state.auditSorting.order === 'asc') {
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

// Fetch and render Port Aliases
async function fetchPortAliases() {
    const tbody = document.getElementById('port-aliases-tbody');
    if (!tbody) return;

    tbody.innerHTML = `
        <tr>
            <td colspan="3" class="text-center text-muted py-3">Loading aliases...</td>
        </tr>
    `;

    try {
        const res = await fetch('/api/ports/aliases');
        if (!res.ok) throw new Error('Failed to fetch port aliases');
        const list = await res.json();
        
        renderPortAliasesTable(list);
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center text-muted py-3">
                    <span style="color: var(--color-danger);">Error: ${err.message}</span>
                </td>
            </tr>
        `;
    }
}

// Render the Port Aliases table rows
function renderPortAliasesTable(list) {
    const tbody = document.getElementById('port-aliases-tbody');
    if (!tbody) return;

    if (list.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center text-muted py-3">No custom port aliases configured.</td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = '';
    list.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="padding: 8px 12px; color: var(--text-primary); font-weight: 500; width: 35%;">${item.port}</td>
            <td class="name-cell" style="padding: 8px 12px; color: var(--text-secondary); width: 45%;">${item.name}</td>
            <td class="actions-cell" style="padding: 8px 12px; text-align: right; width: 20%;">
                <button class="btn-edit-alias" style="background: none; border: none; color: var(--color-primary); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s; margin-right: 6px;">
                    <i data-lucide="edit-2" style="width: 14px; height: 14px;"></i>
                </button>
                <button class="btn-delete-alias" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                    <i data-lucide="trash-2" style="width: 14px; height: 14px;"></i>
                </button>
            </td>
        `;
        
        const nameCell = tr.querySelector('.name-cell');
        const actionsCell = tr.querySelector('.actions-cell');
        const btnEdit = tr.querySelector('.btn-edit-alias');
        const btnDelete = tr.querySelector('.btn-delete-alias');
        
        // Bind edit action (inline edit)
        btnEdit.addEventListener('click', () => {
            nameCell.innerHTML = `<input type="text" class="form-control select-dark edit-name-input" style="width: 100%; background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border-color); border-radius: 4px; padding: 4px 8px; color: var(--text-primary); font-size: 0.85rem;" value="${item.name.replace(/"/g, '&quot;')}">`;
            
            actionsCell.innerHTML = `
                <button class="btn-save-edit" style="background: none; border: none; color: var(--color-success); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s; margin-right: 6px;">
                    <i data-lucide="check" style="width: 14px; height: 14px;"></i>
                </button>
                <button class="btn-cancel-edit" style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                    <i data-lucide="x" style="width: 14px; height: 14px;"></i>
                </button>
            `;
            
            if (window.lucide && typeof window.lucide.createIcons === 'function') {
                window.lucide.createIcons();
            }
            
            const saveBtn = actionsCell.querySelector('.btn-save-edit');
            const cancelBtn = actionsCell.querySelector('.btn-cancel-edit');
            const editInput = nameCell.querySelector('.edit-name-input');
            
            editInput.focus();
            
            saveBtn.addEventListener('click', async () => {
                const newName = editInput.value.trim();
                if (!newName) {
                    showPortAliasStatus('Alias name cannot be empty', 'error');
                    return;
                }
                
                try {
                    const res = await fetch(`/api/ports/aliases?port=${item.port}&name=${encodeURIComponent(newName)}`, { method: 'POST' });
                    if (!res.ok) throw new Error('Save request failed');
                    showPortAliasStatus('Port alias updated successfully', 'success');
                    fetchPortAliases();
                    fetchFlows();
                } catch (err) {
                    showPortAliasStatus(`Error saving: ${err.message}`, 'error');
                }
            });
            
            cancelBtn.addEventListener('click', () => {
                renderPortAliasesTable(list);
            });
            
            editInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    saveBtn.click();
                } else if (e.key === 'Escape') {
                    cancelBtn.click();
                }
            });
        });
        
        // Bind delete action
        btnDelete.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!confirm(`Are you sure you want to delete alias for port ${item.port}?`)) return;
            
            try {
                const res = await fetch(`/api/ports/aliases/${item.port}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                showPortAliasStatus('Alias deleted successfully', 'success');
                fetchPortAliases();
                fetchFlows();
            } catch (err) {
                showPortAliasStatus(`Error deleting: ${err.message}`, 'error');
            }
        });
        
        tbody.appendChild(tr);
    });

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

// Save/Update Port Alias handler
async function handleSavePortAlias(e) {
    e.preventDefault();
    const inputPort = document.getElementById('input-alias-port');
    const inputName = document.getElementById('input-alias-name');
    if (!inputPort || !inputName) return;

    const port = parseInt(inputPort.value);
    const name = inputName.value.trim();

    if (!port || !name) {
        showPortAliasStatus('Please fill in both port and name.', 'error');
        return;
    }

    try {
        const res = await fetch(`/api/ports/aliases?port=${port}&name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('Failed to save port alias');
        
        showPortAliasStatus(`Successfully mapped port ${port} as ${name}`, 'success');
        inputPort.value = '';
        inputName.value = '';
        fetchPortAliases();
        // Refresh flows table to reflect names update immediately
        fetchFlows();
    } catch (err) {
        showPortAliasStatus(`Error saving: ${err.message}`, 'error');
    }
}

// Show status message for Port Alias form
function showPortAliasStatus(message, type) {
    const el = document.getElementById('port-alias-status-message');
    if (!el) return;

    el.style.display = 'block';
    el.innerText = message;
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
    } else {
        el.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
        el.style.color = '#818cf8';
        el.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    }

    // Auto hide after 4 seconds
    setTimeout(() => {
        el.style.display = 'none';
    }, 4000);
}

// Fetch and render IP Aliases
async function fetchIpAliases() {
    const tbody = document.getElementById('ip-aliases-tbody');
    if (!tbody) return;

    tbody.innerHTML = `
        <tr>
            <td colspan="3" class="text-center text-muted py-3">Loading IP aliases...</td>
        </tr>
    `;

    const limit = state.ipAliasesPagination.limit;
    const offset = state.ipAliasesPagination.offset;
    const q = state.ipAliasesPagination.search;
    
    let url = `/api/ips/aliases?limit=${limit}&offset=${offset}`;
    if (q) {
        url += `&q=${encodeURIComponent(q)}`;
    }

    try {
        const res = await fetch(url);
        if (!res.ok) throw new Error('Failed to fetch IP aliases');
        const data = await res.json();
        
        state.ipAliasesPagination.total = data.total;
        
        renderIpAliasesTable(data.records);
        renderIpAliasesPagination(data.total);
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center text-muted py-3">
                    <span style="color: var(--color-danger);">Error: ${err.message}</span>
                </td>
            </tr>
        `;
    }
}

function renderIpAliasesPagination(total) {
    const info = document.getElementById('ip-aliases-pagination-info');
    const btnPrev = document.getElementById('btn-ip-aliases-prev');
    const btnNext = document.getElementById('btn-ip-aliases-next');
    if (!info || !btnPrev || !btnNext) return;
    
    const limit = state.ipAliasesPagination.limit;
    const offset = state.ipAliasesPagination.offset;
    
    const start = total === 0 ? 0 : offset + 1;
    const end = Math.min(total, offset + limit);
    
    info.innerText = `顯示第 ${start} 到 ${end} 筆，共 ${total} 筆`;
    
    btnPrev.disabled = (offset === 0);
    btnNext.disabled = (end >= total);
}

// Render the IP Aliases table rows
function renderIpAliasesTable(list) {
    const tbody = document.getElementById('ip-aliases-tbody');
    if (!tbody) return;

    if (list.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center text-muted py-3">No custom IP aliases configured.</td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = '';
    list.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="padding: 8px 12px; color: var(--text-primary); font-weight: 500; width: 35%;">${item.ip}</td>
            <td class="name-cell" style="padding: 8px 12px; color: var(--text-secondary); width: 45%;">${item.name}</td>
            <td class="actions-cell" style="padding: 8px 12px; text-align: right; width: 20%;">
                <button class="btn-edit-ip-alias" style="background: none; border: none; color: var(--color-primary); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s; margin-right: 6px;">
                    <i data-lucide="edit-2" style="width: 14px; height: 14px;"></i>
                </button>
                <button class="btn-delete-ip-alias" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                    <i data-lucide="trash-2" style="width: 14px; height: 14px;"></i>
                </button>
            </td>
        `;
        
        const nameCell = tr.querySelector('.name-cell');
        const actionsCell = tr.querySelector('.actions-cell');
        const btnEdit = tr.querySelector('.btn-edit-ip-alias');
        const btnDelete = tr.querySelector('.btn-delete-ip-alias');
        
        // Bind edit action (inline edit)
        btnEdit.addEventListener('click', () => {
            // Swap name cell to input
            nameCell.innerHTML = `<input type="text" class="form-control select-dark edit-name-input" style="width: 100%; background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border-color); border-radius: 4px; padding: 4px 8px; color: var(--text-primary); font-size: 0.85rem;" value="${item.name.replace(/"/g, '&quot;')}">`;
            
            // Swap actions to Save / Cancel
            actionsCell.innerHTML = `
                <button class="btn-save-edit" style="background: none; border: none; color: var(--color-success); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s; margin-right: 6px;">
                    <i data-lucide="check" style="width: 14px; height: 14px;"></i>
                </button>
                <button class="btn-cancel-edit" style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                    <i data-lucide="x" style="width: 14px; height: 14px;"></i>
                </button>
            `;
            
            if (window.lucide && typeof window.lucide.createIcons === 'function') {
                window.lucide.createIcons();
            }
            
            const saveBtn = actionsCell.querySelector('.btn-save-edit');
            const cancelBtn = actionsCell.querySelector('.btn-cancel-edit');
            const editInput = nameCell.querySelector('.edit-name-input');
            
            editInput.focus();
            
            saveBtn.addEventListener('click', async () => {
                const newName = editInput.value.trim();
                if (!newName) {
                    showIpAliasStatus('Alias label cannot be empty', 'error');
                    return;
                }
                
                try {
                    const res = await fetch(`/api/ips/aliases?ip=${encodeURIComponent(item.ip)}&name=${encodeURIComponent(newName)}`, { method: 'POST' });
                    if (!res.ok) throw new Error('Save request failed');
                    showIpAliasStatus('IP alias updated successfully', 'success');
                    fetchIpAliases();
                    fetchFlows();
                } catch (err) {
                    showIpAliasStatus(`Error saving: ${err.message}`, 'error');
                }
            });
            
            cancelBtn.addEventListener('click', () => {
                // Restore original rows
                renderIpAliasesTable(list);
            });
            
            editInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    saveBtn.click();
                } else if (e.key === 'Escape') {
                    cancelBtn.click();
                }
            });
        });
        
        // Bind delete action
        btnDelete.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!confirm(`Are you sure you want to delete alias for IP ${item.ip}?`)) return;
            
            try {
                const res = await fetch(`/api/ips/aliases/${encodeURIComponent(item.ip)}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                showIpAliasStatus('IP alias deleted successfully', 'success');
                fetchIpAliases();
                fetchFlows();
            } catch (err) {
                showIpAliasStatus(`Error deleting: ${err.message}`, 'error');
            }
        });
        
        tbody.appendChild(tr);
    });

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

// Save/Update IP Alias handler
async function handleSaveIpAlias(e) {
    e.preventDefault();
    const inputIp = document.getElementById('input-alias-ip');
    const inputName = document.getElementById('input-alias-ip-name');
    if (!inputIp || !inputName) return;

    const ip = inputIp.value.trim();
    const name = inputName.value.trim();

    if (!ip || !name) {
        showIpAliasStatus('Please fill in both IP and alias name.', 'error');
        return;
    }

    try {
        const res = await fetch(`/api/ips/aliases?ip=${encodeURIComponent(ip)}&name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('Failed to save IP alias');
        
        showIpAliasStatus(`Successfully mapped IP ${ip} as ${name}`, 'success');
        inputIp.value = '';
        inputName.value = '';
        fetchIpAliases();
        // Refresh flows table to reflect names update immediately
        fetchFlows();
    } catch (err) {
        showIpAliasStatus(`Error saving: ${err.message}`, 'error');
    }
}

// Show status message for IP Alias form
function showIpAliasStatus(message, type) {
    const el = document.getElementById('ip-alias-status-message');
    if (!el) return;

    el.style.display = 'block';
    el.innerText = message;
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
    } else {
        el.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
        el.style.color = '#818cf8';
        el.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    }

    // Auto hide after 4 seconds
    setTimeout(() => {
        el.style.display = 'none';
    }, 4000);
}

// === Traffic Auditing Module ===

// Fetch all audit rules
async function fetchAuditRules() {
    try {
        const response = await fetch('/api/audit/rules');
        if (!response.ok) throw new Error('Failed to fetch rules');
        const rules = await response.json();
        
        const tbody = els.auditRulesTbody;
        if (!tbody) return;
        
        if (rules.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center text-muted py-4">目前無任何盤查規則</td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = rules.map(rule => {
            const ipAliasSub = rule.ip_alias ? `<div class="domain-subtext" style="font-size: 0.75rem; color: var(--text-muted);">${rule.ip_alias}</div>` : '';
            const ipDisplay = rule.ip ? `<div>${rule.ip}</div>${ipAliasSub}` : '<span class="text-muted">(任意)</span>';
            const portDisplay = rule.port || '<span class="text-muted">(任意)</span>';
            const badgeClass = rule.flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
            const flagText = rule.flag === 'watch' ? '關注' : '異常';
            
            return `
                <tr>
                    <td style="padding: 10px 12px; font-family: var(--font-mono);">${ipDisplay}</td>
                    <td style="padding: 10px 12px; font-family: var(--font-mono);">${portDisplay}</td>
                    <td style="padding: 10px 12px; text-align: center;">
                        <span class="badge ${badgeClass}">${flagText}</span>
                    </td>
                    <td style="padding: 10px 12px; text-align: right;">
                        <button class="btn btn-secondary btn-sm" onclick="deleteAuditRule(${rule.id})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">
                            刪除
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error fetching audit rules:', err);
    }
}

// Submit new rule
async function submitAuditRule() {
    const ip = els.auditInputIp.value.trim();
    const port = els.auditInputPort.value.trim();
    
    const flagEl = document.querySelector('input[name="audit-input-flag"]:checked');
    const flag = flagEl ? flagEl.value : 'watch';
    
    if (!ip && !port) {
        showAuditRuleStatus('IP 與 Port 不能同時為空！', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/audit/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip || null, port: port || null, flag })
        });
        
        const data = await response.json();
        if (response.ok) {
            showAuditRuleStatus('規則儲存成功！', 'success');
            els.auditInputIp.value = '';
            els.auditInputPort.value = '';
            fetchAuditRules();
        } else {
            showAuditRuleStatus(data.detail || '儲存失敗', 'error');
        }
    } catch (err) {
        showAuditRuleStatus(`連線錯誤: ${err.message}`, 'error');
    }
}

// Delete audit rule
async function deleteAuditRule(ruleId) {
    if (!confirm('確定要刪除此比對規則嗎？')) return;
    try {
        const response = await fetch(`/api/audit/rules/${ruleId}`, { method: 'DELETE' });
        if (response.ok) {
            fetchAuditRules();
        } else {
            const data = await response.json();
            alert(data.detail || '刪除失敗');
        }
    } catch (err) {
        alert(`連線錯誤: ${err.message}`);
    }
}

// Fetch last audit status
async function fetchAuditStatus() {
    try {
        const response = await fetch('/api/audit/status');
        if (!response.ok) throw new Error('Failed to fetch audit status');
        const status = await response.json();
        
        els.auditLastRunTime.innerText = status.run_ts || '-';
        if (els.auditNextRunTime) {
            els.auditNextRunTime.innerText = status.next_run_ts || '-';
        }
        els.auditLastRunMatches.innerText = status.records_matched !== undefined ? `${status.records_matched} 筆` : '-';
        els.auditLastRunMessage.innerText = status.message || '-';
        
        const badge = els.auditLastRunStatus;
        if (badge) {
            badge.innerText = status.status === 'success' ? '成功' : (status.status === 'failed' ? '失敗' : '無');
            badge.className = 'badge';
            if (status.status === 'success') {
                badge.classList.add('badge-success');
            } else if (status.status === 'failed') {
                badge.classList.add('badge-danger');
            } else {
                badge.classList.add('badge-info');
            }
        }
    } catch (err) {
        console.error('Error fetching audit status:', err);
    }
}

// Trigger manual audit
async function triggerManualAudit(startTime = null) {
    showAuditTriggerStatus('正在執行流量比對盤查，請稍候...', 'info');
    els.btnTriggerAudit.disabled = true;
    
    try {
        const reqBody = startTime ? { start_time: startTime } : {};
        const response = await fetch('/api/audit/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(reqBody)
        });
        const data = await response.json();
        
        if (response.ok) {
            showAuditTriggerStatus(`盤查成功！共匹配到 ${data.records_matched} 筆流量。`, 'success');
            fetchAuditStatus();
            fetchAuditMatches();
        } else {
            showAuditTriggerStatus(data.detail || '盤查執行失敗', 'error');
        }
    } catch (err) {
        showAuditTriggerStatus(`連線錯誤: ${err.message}`, 'error');
    } finally {
        els.btnTriggerAudit.disabled = false;
    }
}

// Fetch permanently matched records
// Fetch permanently matched records (Anomalous Traffic Report)
async function fetchAuditMatches() {
    const limit = state.auditPagination.limit;
    const offset = state.auditPagination.offset;
    
    let url = `/api/audit/matches?limit=${limit}&offset=${offset}&sort_by=${state.auditSorting.by}&sort_order=${state.auditSorting.order}`;
    if (state.auditFilters.src) url += `&src=${encodeURIComponent(state.auditFilters.src)}`;
    if (state.auditFilters.dst) url += `&dst=${encodeURIComponent(state.auditFilters.dst)}`;
    if (state.auditFilters.port) url += `&port=${encodeURIComponent(state.auditFilters.port)}`;
    if (state.auditFilters.flag) url += `&flag=${encodeURIComponent(state.auditFilters.flag)}`;
    
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to fetch matched records');
        const data = await response.json();
        
        state.auditRecords = data.records; // Cache rules records in state
        state.auditPagination.total = data.total;
        els.auditTotalFiltered.innerText = data.total;
        
        renderAuditMatches(data.records);
        renderAuditPagination(data.total);
    } catch (err) {
        console.error('Error fetching audit matches:', err);
        const tbody = els.auditMatchesTbody;
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="13" class="text-center text-danger py-4">載入失敗: ${err.message}</td></tr>`;
        }
    }
}

// Render matches table
function renderAuditMatches(records) {
    const tbody = els.auditMatchesTbody;
    if (!tbody) return;
    
    if (records.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="13" class="text-center text-muted py-5">無任何比對符合的流量存檔資料</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = records.map((r, idx) => {
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注' : '異常';
        
        const srcDomainSub = r.src_domain ? `<div class="domain-subtext">${r.src_domain}</div>` : '';
        const dstDomainSub = r.dst_domain ? `<div class="domain-subtext">${r.dst_domain}</div>` : '';
        const sportAliasSub = r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : '';
        const dportAliasSub = r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : '';
        
        return `
            <tr class="flow-row" onclick="showAuditFlowDetails(${idx})">
                <td style="padding: 10px 12px; font-family: var(--font-mono); color: var(--text-secondary);">${r.match_ts}</td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">${r.ts}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <span class="badge ${badgeClass}">${flagText}</span>
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono); color: #818cf8;">
                    <div>${r.rule_ip || '(任意)'}</div>
                    ${r.rule_ip_alias ? `<div class="domain-subtext" title="${r.rule_ip_alias}">${r.rule_ip_alias}</div>` : ''}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono); color: #818cf8;">${r.rule_port || '(任意)'}</td>
                <td style="padding: 10px 12px;">
                    <div>${r.src}</div>
                    ${srcDomainSub}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.sport}</div>
                    ${sportAliasSub}
                </td>
                <td style="padding: 10px 12px;">
                    <div>${r.dst}</div>
                    ${dstDomainSub}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.dport}</div>
                    ${dportAliasSub}
                </td>
                <td style="padding: 10px 12px;"><span class="badge badge-info">${r.proto_name}</span></td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono);">${r.packets.toLocaleString()}</td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono); font-weight: 500;">${formatBytes(r.octets)}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <button class="btn-delete-match" data-id="${r.id}" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                        <i data-lucide="trash-2" style="width: 14px; height: 14px;"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
    
    // Bind delete actions
    tbody.querySelectorAll('.btn-delete-match').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const matchId = btn.getAttribute('data-id');
            if (!confirm('確認要刪除此筆異常流量報告？')) return;
            try {
                const res = await fetch(`/api/audit/matches/${encodeURIComponent(matchId)}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                fetchAuditMatches();
            } catch (err) {
                alert(`刪除失敗: ${err.message}`);
            }
        });
    });
    
    // Re-render Lucide icons
    lucide.createIcons();
}

// Render pagination buttons for audit
function renderAuditPagination(total) {
    const el = els.auditPagination;
    if (!el) return;
    
    const limit = state.auditPagination.limit;
    const currentOffset = state.auditPagination.offset;
    const totalPages = Math.ceil(total / limit);
    const currentPage = Math.floor(currentOffset / limit) + 1;
    
    if (totalPages <= 1) {
        el.innerHTML = '';
        return;
    }
    
    let html = '';
    
    // Prev button
    const prevDisabled = currentPage === 1 ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${prevDisabled} onclick="changeAuditPage(${currentPage - 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&laquo;</button>`;
    
    // Page indicators
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);
    
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === currentPage ? 'active' : '';
        const style = i === currentPage ? 'background: var(--color-primary); border-color: var(--color-primary); color: white;' : '';
        html += `<button class="btn btn-secondary btn-sm ${activeClass}" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; ${style}" onclick="changeAuditPage(${i})">${i}</button>`;
    }
    
    // Next button
    const nextDisabled = currentPage === totalPages ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${nextDisabled} onclick="changeAuditPage(${currentPage + 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&raquo;</button>`;
    
    el.innerHTML = html;
}

// Change audit matches page helper
function changeAuditPage(pageNum) {
    const limit = state.auditPagination.limit;
    state.auditPagination.offset = (pageNum - 1) * limit;
    fetchAuditMatches();
}

// Clear matched flows
async function clearAuditMatches() {
    if (!confirm('⚠️ 警告：確定要永久清除所有異常流量報告嗎？此操作將會清空該表，且無法復原！')) return;
    
    try {
        const response = await fetch('/api/audit/matches', { method: 'DELETE' });
        const data = await response.json();
        
        if (response.ok) {
            alert(data.message || '清除成功。');
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        } else {
            alert(data.detail || '清除失敗');
        }
    } catch (err) {
        alert(`連線錯誤: ${err.message}`);
    }
}

// Show details modal specifically for audit records
function showAuditFlowDetails(idx) {
    const r = state.auditRecords[idx];
    if (!r) return;
    
    els.detailId.innerText = r.id || 'N/A';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : 'N/A';
    els.detailType.innerText = r.proto ? r.proto.toUpperCase() : 'N/A';
    els.detailType.className = `value badge ${r.proto === 'ipfix' ? 'badge-info' : (r.proto === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    els.detailExporter.innerText = r.exporter || 'N/A';
    els.detailSrc.innerText = r.src || 'N/A';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || 'N/A';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || r.proto || 'N/A';
    els.detailOctets.innerText = `${formatNumber(r.octets)} bytes (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Parse json_data
    let raw = {};
    if (r.json_data) {
        try {
            raw = JSON.parse(r.json_data);
        } catch (e) {
            raw = { error: "Failed to parse json_data", raw: r.json_data };
        }
    }
    els.detailRawJson.innerText = JSON.stringify(raw, null, 2);
    els.detailsModal.classList.add('active');
}

// Fetch Anomalous Report records for new tab (with filters)
async function fetchAnomalousReport() {
    const limit = state.anomaliesPagination.limit;
    const offset = state.anomaliesPagination.offset;
    
    let url = `/api/audit/matches?limit=${limit}&offset=${offset}&sort_by=${state.auditSorting.by}&sort_order=${state.auditSorting.order}`;
    if (state.anomaliesFilters.src) url += `&src=${encodeURIComponent(state.anomaliesFilters.src)}`;
    if (state.anomaliesFilters.dst) url += `&dst=${encodeURIComponent(state.anomaliesFilters.dst)}`;
    if (state.anomaliesFilters.port) url += `&port=${encodeURIComponent(state.anomaliesFilters.port)}`;
    if (state.anomaliesFilters.flag) url += `&flag=${encodeURIComponent(state.anomaliesFilters.flag)}`;
    
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to fetch anomalous records');
        const data = await response.json();
        
        state.anomaliesRecords = data.records; // Cache in state
        state.anomaliesPagination.total = data.total;
        els.anomaliesTotalFiltered.innerText = data.total;
        
        renderAnomalousReportTable(data.records);
        renderAnomaliesPagination(data.total);
        fetchAnomalousReportStats();
    } catch (err) {
        console.error('Error fetching anomalous reports:', err);
        const tbody = els.anomaliesTbody;
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="12" class="text-center text-danger py-4">載入失敗: ${err.message}</td></tr>`;
        }
    }
}

// Render Anomalous Report table
function renderAnomalousReportTable(records) {
    const tbody = els.anomaliesTbody;
    if (!tbody) return;
    
    if (records.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="12" class="text-center text-muted py-5">無任何異常流量報告資料</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = records.map((r, idx) => {
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注' : '異常';
        
        const srcDomainSub = r.src_domain ? `<div class="domain-subtext">${r.src_domain}</div>` : '';
        const dstDomainSub = r.dst_domain ? `<div class="domain-subtext">${r.dst_domain}</div>` : '';
        const sportAliasSub = r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : '';
        const dportAliasSub = r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : '';
        
        return `
            <tr class="flow-row" onclick="showAnomaliesFlowDetails(${idx})">
                <td style="padding: 10px 12px; font-family: var(--font-mono); color: var(--text-secondary);">${r.match_ts}</td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">${r.ts}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <span class="badge ${badgeClass}">${flagText}</span>
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono); color: #818cf8;">
                    <div>${r.rule_ip || '(任意)'}</div>
                    ${r.rule_ip_alias ? `<div class="domain-subtext" title="${r.rule_ip_alias}">${r.rule_ip_alias}</div>` : ''}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono); color: #818cf8;">${r.rule_port || '(任意)'}</td>
                <td style="padding: 10px 12px;">
                    <div>${r.src}</div>
                    ${srcDomainSub}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.sport}</div>
                    ${sportAliasSub}
                </td>
                <td style="padding: 10px 12px;">
                    <div>${r.dst}</div>
                    ${dstDomainSub}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.dport}</div>
                    ${dportAliasSub}
                </td>
                <td style="padding: 10px 12px;"><span class="badge badge-info">${r.proto_name}</span></td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono);">${r.packets.toLocaleString()}</td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono); font-weight: 500;">${formatBytes(r.octets)}</td>
            </tr>
        `;
    }).join('');
    
    lucide.createIcons();
}

// Pagination logic for anomalies report
function renderAnomaliesPagination(total) {
    const el = els.anomaliesPagination;
    if (!el) return;
    
    const limit = state.anomaliesPagination.limit;
    const currentOffset = state.anomaliesPagination.offset;
    const totalPages = Math.ceil(total / limit);
    const currentPage = Math.floor(currentOffset / limit) + 1;
    
    if (totalPages <= 1) {
        el.innerHTML = '';
        return;
    }
    
    let html = '';
    const prevDisabled = currentPage === 1 ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${prevDisabled} onclick="changeAnomaliesPage(${currentPage - 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&laquo;</button>`;
    
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);
    
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === currentPage ? 'active' : '';
        const style = i === currentPage ? 'background: var(--color-primary); border-color: var(--color-primary); color: white;' : '';
        html += `<button class="btn btn-secondary btn-sm ${activeClass}" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; ${style}" onclick="changeAnomaliesPage(${i})">${i}</button>`;
    }
    
    const nextDisabled = currentPage === totalPages ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${nextDisabled} onclick="changeAnomaliesPage(${currentPage + 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&raquo;</button>`;
    
    el.innerHTML = html;
}

function changeAnomaliesPage(page) {
    const limit = state.anomaliesPagination.limit;
    state.anomaliesPagination.offset = (page - 1) * limit;
    fetchAnomalousReport();
}

// Show details modal specifically for anomalies records
function showAnomaliesFlowDetails(idx) {
    const r = state.anomaliesRecords[idx];
    if (!r) return;
    
    els.detailId.innerText = r.id || 'N/A';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : 'N/A';
    els.detailType.innerText = r.proto ? r.proto.toUpperCase() : 'N/A';
    els.detailType.className = `value badge ${r.proto === 'ipfix' ? 'badge-info' : (r.proto === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    els.detailExporter.innerText = r.exporter || 'N/A';
    els.detailSrc.innerText = r.src || 'N/A';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || 'N/A';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || r.proto || 'N/A';
    els.detailOctets.innerText = `${formatNumber(r.octets)} bytes (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Parse json_data
    let raw = {};
    if (r.json_data) {
        try {
            raw = JSON.parse(r.json_data);
        } catch (e) {
            raw = { error: "Failed to parse json_data", raw: r.json_data };
        }
    }
    els.detailRawJson.innerText = JSON.stringify(raw, null, 2);
    els.detailsModal.classList.add('active');
}

// Show rule status helper
function showAuditRuleStatus(message, type) {
    const el = els.auditRuleStatusMessage;
    if (!el) return;
    
    el.style.display = 'block';
    el.innerText = message;
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
    }
    
    setTimeout(() => {
        el.style.display = 'none';
    }, 4000);
}

// Show manual trigger status helper
function showAuditTriggerStatus(message, type) {
    const el = els.auditTriggerStatus;
    if (!el) return;
    
    el.style.display = 'block';
    el.innerText = message;
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
    
    setTimeout(() => {
        el.style.display = 'none';
    }, 5000);
}

// Fetch statistics for anomalous report view and render the two bar charts
async function fetchAnomalousReportStats() {
    let url = `/api/audit/matches/stats?`;
    if (state.anomaliesFilters.src) url += `&src=${encodeURIComponent(state.anomaliesFilters.src)}`;
    if (state.anomaliesFilters.dst) url += `&dst=${encodeURIComponent(state.anomaliesFilters.dst)}`;
    if (state.anomaliesFilters.port) url += `&port=${encodeURIComponent(state.anomaliesFilters.port)}`;
    if (state.anomaliesFilters.flag) url += `&flag=${encodeURIComponent(state.anomaliesFilters.flag)}`;

    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to fetch stats');
        const data = await response.json();

        // Render Top Sources chart
        renderAnomaliesBarChart(
            'chart-anomalies-sources',
            data.top_sources.map(x => formatChartIPLabel(x.src, x.domain)),
            data.top_sources.map(x => x.bytes),
            '來源流量 (Bytes)',
            'rgba(245, 158, 11, 0.7)',
            'rgba(245, 158, 11, 1)'
        );

        // Render Top Destinations chart
        renderAnomaliesBarChart(
            'chart-anomalies-destinations',
            data.top_destinations.map(x => formatChartIPLabel(x.dst, x.domain)),
            data.top_destinations.map(x => x.bytes),
            '目的流量 (Bytes)',
            'rgba(16, 185, 129, 0.7)',
            'rgba(16, 185, 129, 1)'
        );

        // Render Top Ports chart
        renderAnomaliesBarChart(
            'chart-anomalies-ports',
            data.top_ports.map(x => x.port.toString() + (x.port_name ? ` (${x.port_name})` : '')),
            data.top_ports.map(x => x.bytes),
            '連接埠流量 (Bytes)',
            'rgba(99, 102, 241, 0.7)',
            'rgba(99, 102, 241, 1)'
        );

        // Render Top Protocols chart
        renderAnomaliesBarChart(
            'chart-anomalies-protocols',
            data.ip_protocols.map(x => x.name),
            data.ip_protocols.map(x => x.bytes),
            '協定流量 (Bytes)',
            'rgba(236, 72, 153, 0.7)',
            'rgba(236, 72, 153, 1)'
        );
    } catch (err) {
        console.error('Error fetching anomalous report stats:', err);
    }
}

// Render Anomalous Bar Chart helper
function renderAnomaliesBarChart(canvasId, labels, data, label, bgColor, borderColor) {
    destroyChart(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    state.charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: label,
                data: data,
                backgroundColor: bgColor,
                borderColor: borderColor,
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: '#1f2937',
                    titleColor: '#f3f4f6',
                    bodyColor: '#d1d5db',
                    borderColor: '#374151',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return ` ${context.dataset.label}: ${formatBytes(context.parsed.y)}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#9ca3af',
                        font: {
                            size: 10
                        }
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
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
