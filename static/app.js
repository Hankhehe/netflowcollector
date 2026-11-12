// app.js

// State management
let state = {
    activeTab: 'anomalies', // 'explorer', 'analytics' or 'anomalies'
    filters: {
        table: 'all',
        exporter: '',
        ipDir: 'any',
        ip: '',
        src: '',
        dst: '',
        portDir: 'any',
        port: '',
        sport: '',
        dport: '',
        proto: '',
        conditions: [],
        logic: 'AND',
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
        ipDir: 'any',
        ip: '',
        src: '',
        dst: '',
        portDir: 'any',
        port: '',
        sport: '',
        dport: '',
        proto: '',
        flag: '',
        conditions: [],
        logic: 'AND'
    },
    sorting: {
        by: 'ts',
        order: 'desc'
    },
    auditSorting: {
        by: 'ts',
        order: 'desc'
    },
    records: [], // Cache for current page records
    charts: {},  // Store Chart.js instances
    abortControllers: {} // Active AbortController instances for cancelling stale requests
};

function getAbortSignal(key) {
    if (state.abortControllers[key]) {
        state.abortControllers[key].abort();
    }
    const ctrl = new AbortController();
    state.abortControllers[key] = ctrl;
    return ctrl.signal;
}

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
    btnTabCollector: document.getElementById('btn-tab-collector'),
    viewCollectorSettings: document.getElementById('view-collector-settings'),
    formCollectorSettings: document.getElementById('form-collector-settings'),
    inputSettingNetflowPort: document.getElementById('input-setting-netflow-port'),
    inputSettingIpfixPort: document.getElementById('input-setting-ipfix-port'),
    collectorSettingsStatus: document.getElementById('collector-settings-status'),
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
    
    // Edit Audit Rule Modal
    modalEditAuditRule: document.getElementById('modal-edit-audit-rule'),
    btnCloseEditRuleModal: document.getElementById('btn-close-edit-rule-modal'),
    btnCancelEditRule: document.getElementById('btn-cancel-edit-rule'),
    formEditAuditRule: document.getElementById('form-edit-audit-rule'),
    editRuleId: document.getElementById('edit-rule-id'),
    editRuleSelectIpType: document.getElementById('edit-rule-select-ip-type'),
    editRuleInputIp: document.getElementById('edit-rule-input-ip'),
    editRuleInputPort: document.getElementById('edit-rule-input-port'),
    editRuleErrorMessage: document.getElementById('edit-rule-error-message'),
    
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
    filterAnomaliesIpDir: document.getElementById('filter-anomalies-ip-dir'),
    filterAnomaliesIpType: document.getElementById('filter-anomalies-ip-type'),
    filterAnomaliesIpVal: document.getElementById('filter-anomalies-ip-val'),
    filterAnomaliesPortDir: document.getElementById('filter-anomalies-port-dir'),
    filterAnomaliesPortVal: document.getElementById('filter-anomalies-port-val'),
    filterAnomaliesProto: document.getElementById('filter-anomalies-proto'),
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
    filterIpDir: document.getElementById('filter-ip-dir'),
    filterIpType: document.getElementById('filter-ip-type'),
    filterIpVal: document.getElementById('filter-ip-val'),
    filterPortDir: document.getElementById('filter-port-dir'),
    filterPortVal: document.getElementById('filter-port-val'),
    filterSrc: document.getElementById('filter-src'),
    filterDst: document.getElementById('filter-dst'),
    filterSport: document.getElementById('filter-sport'),
    filterDport: document.getElementById('filter-dport'),
    btnResetFilters: document.getElementById('btn-reset-filters'),
    btnAddFlowCondition: document.getElementById('btn-add-flow-condition'),
    flowConditionsList: document.getElementById('flow-conditions-list'),
    btnAddAnomaliesCondition: document.getElementById('btn-add-anomalies-condition'),
    anomaliesConditionsList: document.getElementById('anomalies-conditions-list'),
    filterProtoGroup: document.getElementById('filter-proto-group'),
    chartContextMenu: document.getElementById('chart-context-menu'),
    
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
    detailRuleSection: document.getElementById('detail-rule-section'),
    detailRuleIp: document.getElementById('detail-rule-ip'),
    detailRulePort: document.getElementById('detail-rule-port'),
    detailMatchFlag: document.getElementById('detail-match-flag'),
    detailMatchTs: document.getElementById('detail-match-ts'),
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
    detailRawJson: document.getElementById('detail-raw-json'),

    // Users & New Settings Elements
    btnTabUsers: document.getElementById('btn-tab-users'),
    viewUserManagement: document.getElementById('view-user-management'),
    inputRetentionDays: document.getElementById('input-retention-days'),
    inputRetentionTime: document.getElementById('input-retention-time'),
    selectRetentionEnabled: document.getElementById('select-retention-enabled'),
    retentionLastRunTime: document.getElementById('retention-last-run-time'),
    retentionNextRunTime: document.getElementById('retention-next-run-time'),
    retentionLastMessage: document.getElementById('retention-last-message'),
    retentionStatusBadge: document.getElementById('retention-status-badge'),
    formRetentionSettings: document.getElementById('form-retention-settings'),
    btnSaveRetention: document.getElementById('btn-save-retention'),
    btnRunRetentionNow: document.getElementById('btn-run-retention-now'),
    retentionStatusAlert: document.getElementById('retention-status-alert'),
    formAddCollectorCidr: document.getElementById('form-add-collector-cidr'),
    inputNewCollectorCidr: document.getElementById('input-new-collector-cidr'),
    inputNewCollectorCidrDesc: document.getElementById('input-new-collector-cidr-desc'),
    collectorCidrsStatus: document.getElementById('collector-cidrs-status'),
    collectorCidrsTbody: document.getElementById('collector-cidrs-tbody'),
    btnOpenAddUser: document.getElementById('btn-open-add-user'),
    usersTbody: document.getElementById('users-tbody'),
    usersStatusMessage: document.getElementById('users-status-message'),
    viewLogin: document.getElementById('view-login'),
    formLogin: document.getElementById('form-login'),
    loginUsername: document.getElementById('login-username'),
    loginPassword: document.getElementById('login-password'),
    loginErrorMessage: document.getElementById('login-error-message'),
    btnDoLogin: document.getElementById('btn-do-login'),
    btnLogout: document.getElementById('btn-logout'),
    btnOpenChangePwd: document.getElementById('btn-open-change-pwd'),
    currentUsername: document.getElementById('current-username'),
    currentUserRole: document.getElementById('current-user-role'),
    userAvatarInitial: document.getElementById('user-avatar-initial'),
    modalAddUser: document.getElementById('modal-add-user'),
    formAddUser: document.getElementById('form-add-user'),
    inputNewUserName: document.getElementById('input-new-user-name'),
    inputNewUserPassword: document.getElementById('input-new-user-password'),
    selectNewUserRole: document.getElementById('select-new-user-role'),
    addUserError: document.getElementById('add-user-error'),
    btnCloseAddUserModal: document.getElementById('btn-close-add-user-modal'),
    btnCancelAddUser: document.getElementById('btn-cancel-add-user'),
    modalResetUserPassword: document.getElementById('modal-reset-user-password'),
    formResetUserPassword: document.getElementById('form-reset-user-password'),
    resetTargetUserId: document.getElementById('reset-target-user-id'),
    resetTargetUsername: document.getElementById('reset-target-username'),
    inputAdminNewPwd: document.getElementById('input-admin-new-pwd'),
    resetPwdError: document.getElementById('reset-pwd-error'),
    btnCloseResetPwdModal: document.getElementById('btn-close-reset-pwd-modal'),
    btnCancelResetPwd: document.getElementById('btn-cancel-reset-pwd'),
    modalChangePassword: document.getElementById('modal-change-password'),
    formChangeOwnPassword: document.getElementById('form-change-own-password'),
    inputCurrentPwd: document.getElementById('input-current-pwd'),
    inputNewOwnPwd: document.getElementById('input-new-own-pwd'),
    inputNewOwnPwdConfirm: document.getElementById('input-new-own-pwd-confirm'),
    changePwdError: document.getElementById('change-pwd-error'),
    btnCloseChangePwdModal: document.getElementById('btn-close-change-pwd-modal'),
    btnCancelChangePwd: document.getElementById('btn-cancel-change-pwd'),
    modalMustChangePassword: document.getElementById('modal-must-change-password'),
    formMustChangePassword: document.getElementById('form-must-change-password'),
    inputForceOldPwd: document.getElementById('input-force-old-pwd'),
    inputForceNewPwd: document.getElementById('input-force-new-pwd'),
    inputForceNewPwdConfirm: document.getElementById('input-force-new-pwd-confirm'),
    forcePwdError: document.getElementById('force-pwd-error')
};

// Sidebar Collapsible Mini-Mode Functions
function initSidebarToggle() {
    const sidebar = document.querySelector('.sidebar');
    const toggleBtn = document.getElementById('btn-toggle-sidebar');
    if (!sidebar || !toggleBtn) return;

    // Check localStorage preference
    const savedState = localStorage.getItem('sidebar-collapsed');
    if (savedState === 'true') {
        sidebar.classList.add('collapsed');
        updateSidebarToggleBtn(true);
    } else {
        updateSidebarToggleBtn(false);
    }

    toggleBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const isCollapsed = sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar-collapsed', isCollapsed ? 'true' : 'false');
        updateSidebarToggleBtn(isCollapsed);

        setTimeout(() => {
            window.dispatchEvent(new Event('resize'));
        }, 260);
    });
}

function setSidebarCollapsed(collapsed) {
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;
    if (collapsed) {
        sidebar.classList.add('collapsed');
    } else {
        sidebar.classList.remove('collapsed');
    }
    localStorage.setItem('sidebar-collapsed', collapsed ? 'true' : 'false');
    updateSidebarToggleBtn(collapsed);
    setTimeout(() => {
        window.dispatchEvent(new Event('resize'));
    }, 260);
}

function updateSidebarToggleBtn(isCollapsed) {
    const toggleBtn = document.getElementById('btn-toggle-sidebar');
    if (!toggleBtn) return;
    toggleBtn.title = isCollapsed ? '展開側邊欄' : '收合側邊欄';
    const closeIcon = toggleBtn.querySelector('.toggle-icon-collapse');
    const openIcon = toggleBtn.querySelector('.toggle-icon-expand');
    if (closeIcon) closeIcon.style.display = isCollapsed ? 'none' : 'block';
    if (openIcon) openIcon.style.display = isCollapsed ? 'block' : 'none';
}

// Initialization
document.addEventListener('DOMContentLoaded', async () => {
    // Re-initialize Lucide Icons
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        lucide.createIcons();
    }
    
    initSidebarToggle();
    setupConditionBuilders();
    renderConditions('flow');
    renderConditions('anomalies');
    setupEventListeners();
    setupHeaderSorting();
    updateHeaderSortIcons();
    setupAuditHeaderSorting();
    updateAuditHeaderSortIcons();
    setupColumnToggles();
    setupDropdowns();
    
    // Check authentication first
    const isAuth = await checkAuth();
    if (isAuth) {
        fetchExporterDropdown();
        fetchPortAliases();
        fetchIpAliases();
        switchTab('anomalies');
    }
});

// Setup Event Listeners
function setupEventListeners() {
    // IP Type Select Show/Hide Inputs for General
    const filterIpType = document.getElementById('filter-ip-type');
    const filterIpVal = document.getElementById('filter-ip-val');
    if (filterIpType && filterIpVal) {
        filterIpType.addEventListener('change', () => {
            filterIpVal.style.display = filterIpType.value === 'custom' ? 'block' : 'none';
            if (filterIpType.value !== 'custom') {
                filterIpVal.value = '';
            }
        });
    }

    // IP Type Select Show/Hide Inputs for Anomalies
    const filterAnomaliesIpType = document.getElementById('filter-anomalies-ip-type');
    const filterAnomaliesIpVal = document.getElementById('filter-anomalies-ip-val');
    if (filterAnomaliesIpType && filterAnomaliesIpVal) {
        filterAnomaliesIpType.addEventListener('change', () => {
            filterAnomaliesIpVal.style.display = filterAnomaliesIpType.value === 'custom' ? 'block' : 'none';
            if (filterAnomaliesIpType.value !== 'custom') {
                filterAnomaliesIpVal.value = '';
            }
        });
    }

    // Legacy IP Type fallback handlers
    const filterSrcType = document.getElementById('filter-src-type');
    const filterSrcInput = document.getElementById('filter-src');
    if (filterSrcType && filterSrcInput && filterSrcInput.type !== 'hidden') {
        filterSrcType.addEventListener('change', () => {
            filterSrcInput.style.display = filterSrcType.value === 'custom' ? 'block' : 'none';
            if (filterSrcType.value !== 'custom') {
                filterSrcInput.value = '';
            }
        });
    }

    const filterDstType = document.getElementById('filter-dst-type');
    const filterDstInput = document.getElementById('filter-dst');
    if (filterDstType && filterDstInput && filterDstInput.type !== 'hidden') {
        filterDstType.addEventListener('change', () => {
            filterDstInput.style.display = filterDstType.value === 'custom' ? 'block' : 'none';
            if (filterDstType.value !== 'custom') {
                filterDstInput.value = '';
            }
        });
    }

    const auditSelectIpType = document.getElementById('audit-select-ip-type');
    const auditInputIp = document.getElementById('audit-input-ip');
    if (auditSelectIpType && auditInputIp) {
        auditSelectIpType.addEventListener('change', () => {
            auditInputIp.style.display = auditSelectIpType.value === 'custom' ? 'block' : 'none';
            if (auditSelectIpType.value !== 'custom') {
                auditInputIp.value = '';
            }
        });
    }

    // Close chart context menu on click outside or Escape
    document.addEventListener('click', (e) => {
        const menu = document.getElementById('chart-context-menu');
        if (menu && menu.style.display !== 'none' && !e.target.closest('#chart-context-menu')) {
            hideChartContextMenu();
        }
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideChartContextMenu();
        }
    });

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
            const sidebar = document.querySelector('.sidebar');
            if (sidebar && sidebar.classList.contains('collapsed')) {
                setSidebarCollapsed(false);
            }
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

    if (els.btnTabCollector) {
        els.btnTabCollector.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('collector');
        });
    }

    if (els.btnTabUsers) {
        els.btnTabUsers.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('users');
        });
    }

    // Retention Policy Listeners
    if (els.formRetentionSettings) {
        els.formRetentionSettings.addEventListener('submit', (e) => {
            e.preventDefault();
            saveRetentionSettings();
        });
    }

    if (els.btnRunRetentionNow) {
        els.btnRunRetentionNow.addEventListener('click', () => {
            runRetentionNow();
        });
    }

    // Collector CIDR Listeners
    if (els.formAddCollectorCidr) {
        els.formAddCollectorCidr.addEventListener('submit', (e) => {
            e.preventDefault();
            addCollectorCidr();
        });
    }

    // User Management Listeners
    if (els.btnOpenAddUser) {
        els.btnOpenAddUser.addEventListener('click', () => {
            openAddUserModal();
        });
    }

    if (els.btnCloseAddUserModal) {
        els.btnCloseAddUserModal.addEventListener('click', closeAddUserModal);
    }
    if (els.btnCancelAddUser) {
        els.btnCancelAddUser.addEventListener('click', closeAddUserModal);
    }
    if (els.formAddUser) {
        els.formAddUser.addEventListener('submit', (e) => {
            e.preventDefault();
            submitCreateUser();
        });
    }

    // User Password Reset Modal Listeners
    if (els.btnCloseResetPwdModal) {
        els.btnCloseResetPwdModal.addEventListener('click', closeResetPwdModal);
    }
    if (els.btnCancelResetPwd) {
        els.btnCancelResetPwd.addEventListener('click', closeResetPwdModal);
    }
    if (els.formResetUserPassword) {
        els.formResetUserPassword.addEventListener('submit', (e) => {
            e.preventDefault();
            submitResetUserPassword();
        });
    }

    // Change Own Password Modal Listeners
    if (els.btnOpenChangePwd) {
        els.btnOpenChangePwd.addEventListener('click', () => {
            openChangePwdModal();
        });
    }
    if (els.btnCloseChangePwdModal) {
        els.btnCloseChangePwdModal.addEventListener('click', closeChangePwdModal);
    }
    if (els.btnCancelChangePwd) {
        els.btnCancelChangePwd.addEventListener('click', closeChangePwdModal);
    }
    if (els.formChangeOwnPassword) {
        els.formChangeOwnPassword.addEventListener('submit', (e) => {
            e.preventDefault();
            submitChangeOwnPassword();
        });
    }

    // Force Password Change Listener (First login)
    if (els.formMustChangePassword) {
        els.formMustChangePassword.addEventListener('submit', (e) => {
            e.preventDefault();
            submitForceChangePassword();
        });
    }

    // Auth Login & Logout
    if (els.formLogin) {
        els.formLogin.addEventListener('submit', (e) => {
            e.preventDefault();
            handleLogin();
        });
    }

    if (els.btnLogout) {
        els.btnLogout.addEventListener('click', () => {
            handleLogout();
        });
    }

    if (els.formCollectorSettings) {
        els.formCollectorSettings.addEventListener('submit', (e) => {
            e.preventDefault();
            saveCollectorSettings();
        });
    }

    if (els.auditRuleForm) {
        els.auditRuleForm.addEventListener('submit', (e) => {
            e.preventDefault();
            submitAuditRule();
        });
    }

    // Edit Audit Rule Modal listeners
    if (els.editRuleSelectIpType && els.editRuleInputIp) {
        els.editRuleSelectIpType.addEventListener('change', () => {
            els.editRuleInputIp.style.display = els.editRuleSelectIpType.value === 'custom' ? 'block' : 'none';
            if (els.editRuleSelectIpType.value !== 'custom') {
                els.editRuleInputIp.value = '';
            }
        });
    }

    if (els.btnCloseEditRuleModal) {
        els.btnCloseEditRuleModal.addEventListener('click', closeEditRuleModal);
    }
    if (els.btnCancelEditRule) {
        els.btnCancelEditRule.addEventListener('click', closeEditRuleModal);
    }
    if (els.formEditAuditRule) {
        els.formEditAuditRule.addEventListener('submit', submitEditAuditRule);
    }
    window.addEventListener('click', (e) => {
        if (els.modalEditAuditRule && e.target === els.modalEditAuditRule) {
            closeEditRuleModal();
        }
    });

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
            applyAnomaliesFiltersFromForm();
            renderConditions('anomalies');
            state.anomaliesPagination.offset = 0;
            fetchAnomalousReport();
        });
    }

    if (els.btnResetAnomaliesSearch) {
        els.btnResetAnomaliesSearch.addEventListener('click', () => {
            state.anomaliesFilters.conditions = [];
            state.anomaliesFilters.logic = 'AND';
            renderConditions('anomalies');
            const aFlagEl = document.getElementById('filter-anomalies-flag');
            if (aFlagEl) aFlagEl.value = '';
            
            applyAnomaliesFiltersFromForm();
            state.anomaliesPagination.offset = 0;
            fetchAnomalousReport();
        });
    }

    if (els.btnExportAnomalies) {
        els.btnExportAnomalies.addEventListener('click', () => {
            let url = `/api/audit/matches/export?`;
            const params = [];
            if (state.anomaliesFilters.ip) params.push(`ip=${encodeURIComponent(state.anomaliesFilters.ip)}`);
            if (state.anomaliesFilters.src) params.push(`src=${encodeURIComponent(state.anomaliesFilters.src)}`);
            if (state.anomaliesFilters.dst) params.push(`dst=${encodeURIComponent(state.anomaliesFilters.dst)}`);
            if (state.anomaliesFilters.port) params.push(`port=${encodeURIComponent(state.anomaliesFilters.port)}`);
            if (state.anomaliesFilters.sport) params.push(`sport=${encodeURIComponent(state.anomaliesFilters.sport)}`);
            if (state.anomaliesFilters.dport) params.push(`dport=${encodeURIComponent(state.anomaliesFilters.dport)}`);
            if (state.anomaliesFilters.proto) params.push(`proto=${encodeURIComponent(state.anomaliesFilters.proto)}`);
            if (state.anomaliesFilters.flag) params.push(`flag=${encodeURIComponent(state.anomaliesFilters.flag)}`);
            
            // Dynamic multi-conditions
            if (state.anomaliesFilters.conditions && state.anomaliesFilters.conditions.length > 0) {
                const validConds = state.anomaliesFilters.conditions.map(c => {
                    let finalVal = c.val;
                    if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                        if (c.ipType && c.ipType !== 'custom') {
                            finalVal = c.ipType;
                        }
                    }
                    return { field: c.field, val: finalVal };
                }).filter(c => c.val && String(c.val).trim() !== '');

                if (validConds.length > 0) {
                    params.push(`conditions=${encodeURIComponent(JSON.stringify(validConds))}`);
                    params.push(`logic=${encodeURIComponent(state.anomaliesFilters.logic || 'AND')}`);
                }
            }

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
                showAuditRuleStatus('盤查規則備份檔已成功下載', 'success');
            } catch (err) {
                showAuditRuleStatus(`匯出失敗: ${err.message}`, 'error');
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
                        throw new Error('無效的備份檔格式（需為規則的 JSON 陣列）');
                    }

                    const res = await fetch('/api/audit/rules/import', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    
                    if (res.ok) {
                        showAuditRuleStatus(data.message || '匯入成功', 'success');
                        fetchAuditRules(); // Reload rule table
                    } else {
                        showAuditRuleStatus(data.detail || '匯入失敗', 'error');
                    }
                } catch (err) {
                    showAuditRuleStatus(`解析匯入檔案失敗: ${err.message}`, 'error');
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
        state.filters.startTime = toTaiwanLocalTimestamp(globalStart.value);
        state.pagination.offset = 0; // Reset pagination
        updateTimeRangeSubtitle();
        refreshData();
    });
    
    globalEnd.addEventListener('change', () => {
        state.filters.endTime = toTaiwanLocalTimestamp(globalEnd.value);
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
        fetchExporterDropdown();
        refreshData();
    });
    
    // Filters form submit & reset
    els.filterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        applyFiltersFromForm();
        renderConditions('flow');
        state.pagination.offset = 0;
        refreshData();
    });
    
    els.btnResetFilters.addEventListener('click', () => {
        els.filterForm.reset();
        state.filters.conditions = [];
        state.filters.logic = 'AND';
        renderConditions('flow');

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
                showIpAliasStatus('別名備份檔已成功下載', 'success');
            } catch (err) {
                showIpAliasStatus(`匯出失敗: ${err.message}`, 'error');
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
                        throw new Error('無效的備份檔格式（缺少 ip_aliases 或 port_aliases）');
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
                    showIpAliasStatus(`匯入失敗: ${err.message}`, 'error');
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
            if (!confirm('您確定要清空所有自訂 IP 與 Port 別名嗎？此動作將無法復原。')) return;
            
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
                showIpAliasStatus(`清除失敗: ${err.message}`, 'error');
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
    const isSettingsTab = ['data-management', 'aliases', 'audit', 'anomalies', 'collector', 'users'].includes(tabName);
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
    if (els.btnTabCollector) els.btnTabCollector.classList.remove('active');
    if (els.btnTabUsers) els.btnTabUsers.classList.remove('active');
    
    els.viewExplorer.classList.remove('active');
    els.viewAnalytics.classList.remove('active');
    if (els.viewAnomalies) els.viewAnomalies.classList.remove('active');
    if (els.viewDataManagement) els.viewDataManagement.classList.remove('active');
    if (els.viewAliasManager) els.viewAliasManager.classList.remove('active');
    if (els.viewAudit) els.viewAudit.classList.remove('active');
    if (els.viewCollectorSettings) els.viewCollectorSettings.classList.remove('active');
    if (els.viewUserManagement) els.viewUserManagement.classList.remove('active');
    
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
            fetchRetentionSettings();
        } else if (tabName === 'aliases') {
            activeBtn = els.btnTabAliases;
            activeView = els.viewAliasManager;
        } else if (tabName === 'audit') {
            activeBtn = els.btnTabAudit;
            activeView = els.viewAudit;
            fetchAuditRules();
            fetchAuditStatus();
            fetchAuditMatches();
        } else if (tabName === 'collector') {
            activeBtn = els.btnTabCollector;
            activeView = els.viewCollectorSettings;
            fetchCollectorSettings();
            fetchCollectorCidrs();
        } else if (tabName === 'users') {
            activeBtn = els.btnTabUsers;
            activeView = els.viewUserManagement;
            fetchUsersList();
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

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

// Update time summary subtitle
function updateTimeRangeSubtitle() {
    const range = state.filters.timeRange;
    let label = '過去 24 小時流量總覽';
    if (range === '1h') label = '過去 1 小時流量總覽';
    if (range === '7d') label = '過去 7 天流量總覽';
    if (range === 'all') label = '所有歷史流量總覽';
    if (range === 'custom') {
        const startVal = document.getElementById('global-start-time').value;
        const endVal = document.getElementById('global-end-time').value;
        if (startVal && endVal) {
            label = `自 ${startVal.replace('T', ' ')} 至 ${endVal.replace('T', ' ')} 之流量總覽`;
        } else {
            label = '自訂時間區間之流量總覽';
        }
    }
    els.timeRangeSummary.innerText = label;
}

// Read form elements into state filters
function applyFiltersFromForm() {
    state.filters.table = getSelectedTables();
    state.filters.exporter = getSelectedExporters();
    state.filters.proto = getSelectedProtocols();

    // Read current inputs in condition builder into state.filters.conditions
    const container = document.getElementById('flow-conditions-list');
    if (container) {
        const rows = container.querySelectorAll('.condition-row');
        const conds = [];
        rows.forEach(row => {
            const fieldEl = row.querySelector('.cond-field');
            const ipTypeEl = row.querySelector('.cond-iptype');
            const valEl = row.querySelector('.cond-val');
            if (fieldEl) {
                const field = fieldEl.value;
                const ipType = ipTypeEl ? ipTypeEl.value : 'custom';
                let val = valEl ? valEl.value.trim() : '';
                if (['src_ip', 'dst_ip', 'any_ip'].includes(field) && ipType !== 'custom') {
                    val = ipType;
                }
                conds.push({
                    id: row.getAttribute('data-id') || genConditionId(),
                    field: field,
                    ipType: ipType,
                    val: val
                });
            }
        });
        if (!state.filters.conditions) {
            state.filters.conditions = conds;
        } else {
            state.filters.conditions.length = 0;
            state.filters.conditions.push(...conds);
        }
    }
}

// Read anomalies form elements into state anomalies filters
function applyAnomaliesFiltersFromForm() {
    const flagEl = document.getElementById('filter-anomalies-flag');
    if (flagEl) state.anomaliesFilters.flag = flagEl.value.trim();

    const container = document.getElementById('anomalies-conditions-list');
    if (container) {
        const rows = container.querySelectorAll('.condition-row');
        const conds = [];
        rows.forEach(row => {
            const fieldEl = row.querySelector('.cond-field');
            const ipTypeEl = row.querySelector('.cond-iptype');
            const valEl = row.querySelector('.cond-val');
            if (fieldEl) {
                const field = fieldEl.value;
                const ipType = ipTypeEl ? ipTypeEl.value : 'custom';
                let val = valEl ? valEl.value.trim() : '';
                if (['src_ip', 'dst_ip', 'any_ip'].includes(field) && ipType !== 'custom') {
                    val = ipType;
                }
                conds.push({
                    id: row.getAttribute('data-id') || genConditionId(),
                    field: field,
                    ipType: ipType,
                    val: val
                });
            }
        });
        if (!state.anomaliesFilters.conditions) {
            state.anomaliesFilters.conditions = conds;
        } else {
            state.anomaliesFilters.conditions.length = 0;
            state.anomaliesFilters.conditions.push(...conds);
        }
    }
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
async function fetchExporterDropdown(skipRefresh = false) {
    try {
        const res = await fetch('/api/exporters');
        if (!res.ok) throw new Error('Failed to fetch exporters list');
        const exporters = await res.json();
        
        const container = document.getElementById('filter-exporter-group');
        if (container) {
            const prevCheckboxes = container.querySelectorAll('input[type="checkbox"]');
            const prevChecked = new Set();
            let allWereChecked = true;
            if (prevCheckboxes.length > 0) {
                prevCheckboxes.forEach(cb => {
                    if (cb.checked) prevChecked.add(cb.value);
                    else allWereChecked = false;
                });
            }

            container.innerHTML = '';
            exporters.forEach(ip => {
                const label = document.createElement('label');
                label.className = 'checkbox-label';
                const isChecked = allWereChecked || prevChecked.has(ip);
                label.innerHTML = `<input type="checkbox" name="exporter" value="${ip}" ${isChecked ? 'checked' : ''}> ${ip}`;
                container.appendChild(label);
            });
            
            // Register change event listener on new checkboxes to update trigger label
            container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                cb.addEventListener('change', updateDropdownLabels);
            });
            updateDropdownLabels();
            
            if (!skipRefresh) {
                refreshData();
            }
        }
    } catch (err) {
        console.error('Error fetching exporters dropdown:', err);
    }
}

// Helper to update KPI DOM elements from stats payload
function updateKpiDom(data) {
    if (!data) return;
    if (els.kpiTotalFlows) els.kpiTotalFlows.innerText = formatNumber(data.total_flows);
    if (els.kpiTotalBytes) els.kpiTotalBytes.innerText = formatBytes(data.total_bytes);
    if (els.kpiTotalPackets) els.kpiTotalPackets.innerText = formatNumber(data.total_packets);
    if (els.kpiTotalExporters && Array.isArray(data.top_exporters)) {
        els.kpiTotalExporters.innerText = formatNumber(data.top_exporters.length);
    }
}

// Refresh active tab and KPI totals
function refreshData() {
    applyFiltersFromForm();
    if (state.activeTab === 'explorer') {
        fetchKPIs();
        fetchFlows();
    } else if (state.activeTab === 'analytics') {
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
    if (state.filters.ip) params.append('ip', state.filters.ip);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.port) params.append('port', state.filters.port);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    // Dynamic conditions
    if (state.filters.conditions && state.filters.conditions.length > 0) {
        const validConds = state.filters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            params.append('conditions', JSON.stringify(validConds));
            params.append('logic', state.filters.logic || 'AND');
        }
    }

    try {
        const signal = getAbortSignal('stats');
        const res = await fetch(`/api/stats?${params.toString()}`, { signal });
        if (!res.ok) throw new Error('Failed to fetch KPI stats');
        const data = await res.json();
        updateKpiDom(data);
    } catch (err) {
        if (err.name === 'AbortError') return;
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
    if (state.filters.ip) params.append('ip', state.filters.ip);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.port) params.append('port', state.filters.port);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    // Dynamic conditions
    if (state.filters.conditions && state.filters.conditions.length > 0) {
        const validConds = state.filters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            params.append('conditions', JSON.stringify(validConds));
            params.append('logic', state.filters.logic || 'AND');
        }
    }

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
                正在載入流量記錄...
            </td>
        </tr>
    `;
    
    const params = getFlowQueryParams();
    params.append('limit', state.pagination.limit);
    params.append('offset', state.pagination.offset);
    
    try {
        const signal = getAbortSignal('flows');
        const res = await fetch(`/api/flows?${params.toString()}`, { signal });
        if (!res.ok) throw new Error('查詢流量記錄失敗');
        const data = await res.json();
        
        state.records = data.records;
        state.pagination.total = data.total;
        
        renderFlowsTable();
        renderPagination();
    } catch (err) {
        if (err.name === 'AbortError') return;
        els.flowsTbody.innerHTML = `
            <tr>
                <td colspan="${visibleColsCount}" class="text-center text-muted py-5">
                    <span style="color: var(--color-danger)">載入流量記錄失敗: ${err.message}</span>
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
                    查無符合條件之流量記錄。請確認流量收集器已啟動並正常接收流量。
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
        const typeLabel = r.type ? r.type.toUpperCase() : '已聚合';
        
        const timeFormatted = r.ts ? formatSqlTimestamp(r.ts) : '已聚合';
        const protocolText = r.proto_name || '已聚合';
        
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

// Standard Taiwan time (Asia/Taipei UTC+8) formatter
function formatSqlTimestamp(tsString) {
    if (!tsString) return '';
    return String(tsString).replace('T', ' ').replace('Z', '').substring(0, 19);
}

// Show modal dialog containing complete details of clicked row
function showFlowDetails(idx) {
    const r = state.records[idx];
    if (!r) return;
    
    if (els.detailRuleSection) {
        els.detailRuleSection.style.display = 'none';
    }
    
    els.detailId.innerText = r.id || '不適用 (聚合資料)';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : '已聚合';
    els.detailType.innerText = r.type ? r.type.toUpperCase() : '已聚合';
    els.detailType.className = `value badge ${r.type === 'ipfix' ? 'badge-info' : (r.type === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    els.detailExporter.innerText = r.exporter || '已聚合';
    els.detailSrc.innerText = r.src || '已聚合';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || '已聚合';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || '已聚合';
    els.detailOctets.innerText = `${formatNumber(r.octets)} 位元組 (${formatBytes(r.octets)})`;
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

// Helper to format Alias labels in charts (truncate long names to keep chart heights consistent)
function formatChartAliasLabel(name) {
    if (!name) return '';
    const maxLen = 18;
    return name.length > maxLen ? name.substring(0, maxLen) + '...' : name;
}

// Fetch stats and render analytics charts
async function fetchStats() {
    const params = new URLSearchParams({
        table: state.filters.table,
        time_range: state.filters.timeRange
    });
    if (state.filters.exporter) params.append('exporter', state.filters.exporter);
    if (state.filters.ip) params.append('ip', state.filters.ip);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.port) params.append('port', state.filters.port);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    // Dynamic conditions
    if (state.filters.conditions && state.filters.conditions.length > 0) {
        const validConds = state.filters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            params.append('conditions', JSON.stringify(validConds));
            params.append('logic', state.filters.logic || 'AND');
        }
    }

    try {
        const signal = getAbortSignal('stats');
        const res = await fetch(`/api/stats?${params.toString()}`, { signal });
        if (!res.ok) throw new Error('Failed to fetch statistics');
        const data = await res.json();
        
        updateKpiDom(data);
        renderTimeChart(data.traffic_over_time);
        renderBarChart(
            'chart-top-sources', 
            'Top Sources', 
            data.top_sources.map(x => formatChartIPLabel(x.src, x.domain)), 
            data.top_sources.map(x => x.bytes),
            { itemType: 'ip', defaultDir: 'src', viewType: 'general', rawItems: data.top_sources.map(x => x.src) }
        );
        renderBarChart(
            'chart-top-destinations', 
            'Top Destinations', 
            data.top_destinations.map(x => formatChartIPLabel(x.dst, x.domain)), 
            data.top_destinations.map(x => x.bytes),
            { itemType: 'ip', defaultDir: 'dst', viewType: 'general', rawItems: data.top_destinations.map(x => x.dst) }
        );
        renderBarChart(
            'chart-top-src-ports', 
            'Top 10 Source Ports', 
            data.top_source_ports.map(x => x.sport.toString() + (x.port_name ? ` (${x.port_name})` : '')), 
            data.top_source_ports.map(x => x.bytes),
            { itemType: 'port', defaultDir: 'src', viewType: 'general', rawItems: data.top_source_ports.map(x => x.sport) }
        );
        renderBarChart(
            'chart-top-dst-ports', 
            'Top 10 Destination Ports', 
            data.top_destination_ports.map(x => x.dport.toString() + (x.port_name ? ` (${x.port_name})` : '')), 
            data.top_destination_ports.map(x => x.bytes),
            { itemType: 'port', defaultDir: 'dst', viewType: 'general', rawItems: data.top_destination_ports.map(x => x.dport) }
        );
        const topAliases = data.top_aliases || [];
        renderBarChart(
            'chart-top-aliases',
            '前十大 IP 別名',
            topAliases.map(x => formatChartAliasLabel(x.name)),
            topAliases.map(x => x.bytes),
            { 
                itemType: 'alias', 
                defaultDir: 'any', 
                viewType: 'general', 
                rawItems: topAliases.map(x => x.name),
                flowCounts: topAliases.map(x => x.flows)
            }
        );
        renderDoughnutChart('chart-exporters', data.top_exporters.map(x => x.exporter), data.top_exporters.map(x => x.flows));
        
    } catch (err) {
        if (err.name === 'AbortError') return;
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
                    label: '傳輸量 (Bytes)',
                    data: bytesData,
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    yAxisID: 'y-bytes',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2
                },
                {
                    label: '封包數',
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

function renderBarChart(canvasId, title, labels, data, drillMeta) {
    destroyChart(canvasId);
    
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const ctx2d = ctx.getContext('2d');
    
    const ds = {
        label: '傳輸量 (Bytes)',
        data: data,
        backgroundColor: 'rgba(99, 102, 241, 0.75)',
        borderColor: '#6366f1',
        borderWidth: 1,
        borderRadius: 4
    };
    if (drillMeta) {
        ds.drillMeta = drillMeta;
    }

    state.charts[canvasId] = new Chart(ctx2d, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [ds]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (event, elements, chart) => {
                if (!elements || elements.length === 0) return;
                const index = elements[0].index;
                const meta = chart.data.datasets[0].drillMeta;
                if (!meta) return;
                const rawVal = (meta.rawItems && meta.rawItems[index] !== undefined) ? meta.rawItems[index] : chart.data.labels[index];
                showChartContextMenu(event.native || event, meta.itemType, rawVal, meta.viewType, meta.defaultDir);
            },
            onHover: (event, chartElement) => {
                const target = event.native ? event.native.target : (event.target || (event.chart && event.chart.canvas));
                if (target) {
                    target.style.cursor = chartElement[0] ? 'pointer' : 'default';
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            if (!context || !context.length) return '';
                            const meta = context[0].chart.data.datasets[0].drillMeta;
                            if (meta && meta.itemType === 'alias' && meta.rawItems && meta.rawItems[context[0].dataIndex] !== undefined) {
                                return meta.rawItems[context[0].dataIndex];
                            }
                            return context[0].label;
                        },
                        label: function(context) {
                            let label = '傳輸量: ' + formatBytes(context.parsed.y);
                            const meta = context.chart.data.datasets[0].drillMeta;
                            if (meta && meta.flowCounts && meta.flowCounts[context.dataIndex] !== undefined) {
                                label += ` (${formatNumber(meta.flowCounts[context.dataIndex])} flows)`;
                            }
                            return label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#9ca3af',
                        maxRotation: 45,
                        minRotation: 0
                    }
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

function renderDoughnutChart(canvasId, labels, data, drillMeta) {
    destroyChart(canvasId);
    if (labels.length === 0) return; // avoid empty doughnut bug
    
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const ctx2d = ctx.getContext('2d');

    const ds = {
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
    };
    if (drillMeta) {
        ds.drillMeta = drillMeta;
    }

    state.charts[canvasId] = new Chart(ctx2d, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [ds]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (event, elements, chart) => {
                if (!elements || elements.length === 0) return;
                const index = elements[0].index;
                const meta = chart.data.datasets[0].drillMeta;
                if (!meta) return;
                const rawVal = (meta.rawItems && meta.rawItems[index] !== undefined) ? meta.rawItems[index] : chart.data.labels[index];
                showChartContextMenu(event.native || event, meta.itemType, rawVal, meta.viewType, meta.defaultDir);
            },
            onHover: (event, chartElement) => {
                const target = event.native ? event.native.target : (event.target || (event.chart && event.chart.canvas));
                if (target) {
                    target.style.cursor = chartElement[0] ? 'pointer' : 'default';
                }
            },
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
            labelProto.innerText = '無';
        } else if (checkedProtos.length === protoCheckboxes.length) {
            labelProto.innerText = '所有協定';
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
            labelTable.innerText = '無';
        } else if (checkedTables.length === tableCheckboxes.length) {
            labelTable.innerText = '所有資料來源';
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
            labelExporter.innerText = '無';
        } else if (checkedExporters.length === exporterCheckboxes.length) {
            labelExporter.innerText = '所有 Exporter';
        } else {
            labelExporter.innerText = checkedExporters.length > 2 
                ? `${checkedExporters.length} 個 Exporter` 
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
            labelCols.innerText = '無';
        } else if (checkedCols.length === colCheckboxes.length) {
            labelCols.innerText = '所有欄位';
        } else {
            labelCols.innerText = `${checkedCols.length} 個欄位`;
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
    // If all or none are checked, treat as All Exporters (no filter restriction)
    if (checked.length === checkboxes.length || checked.length === 0) {
        return '';
    }
    return checked.join(',');
}

// Convert local datetime-local string input value to Taiwan time format YYYY-MM-DD HH:MM:SS
function toTaiwanLocalTimestamp(localStr) {
    if (!localStr) return '';
    let clean = localStr.replace('T', ' ').trim();
    if (clean.length === 16) clean += ':00';
    return clean;
}

// Execute Manual Data Cleanup API POST Request
async function executeCleanup() {
    const beforeVal = els.cleanupBeforeDate.value;
    if (!beforeVal) {
        showCleanupStatus('請選擇日期與時間。', 'error');
        return;
    }
    
    const localDate = toTaiwanLocalTimestamp(beforeVal);
    if (!localDate) {
        showCleanupStatus('所選日期格式無效。', 'error');
        return;
    }
    
    if (!confirm(`您確定要刪除所有在 ${localDate} (台灣時間) 之前的流量資料嗎？此操作將無法復原。`)) {
        return;
    }
    
    showCleanupStatus('正在執行資料清理...', 'info');
    els.btnExecuteCleanup.disabled = true;
    
    try {
        const response = await fetch(`/api/flows/delete?before=${encodeURIComponent(localDate)}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        if (response.ok) {
            showCleanupStatus(data.message || '資料清理已成功發起。', 'success');
            els.cleanupBeforeDate.value = ''; // Reset input
            fetchRetentionSettings(); // Refresh retention card status
        } else {
            showCleanupStatus(data.detail || '發起資料清理失敗。', 'error');
        }
    } catch (err) {
        showCleanupStatus(`網路錯誤: ${err.message}`, 'error');
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
            <td colspan="3" class="text-center text-muted py-3">正在載入別名...</td>
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
                <td colspan="3" class="text-center text-muted py-3">尚未設定任何自訂 Port 別名。</td>
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
                    showPortAliasStatus('別名名稱不得為空', 'error');
                    return;
                }
                
                try {
                    const res = await fetch(`/api/ports/aliases?port=${item.port}&name=${encodeURIComponent(newName)}`, { method: 'POST' });
                    if (!res.ok) throw new Error('Save request failed');
                    showPortAliasStatus('Port 別名已成功更新', 'success');
                    fetchPortAliases();
                    fetchFlows();
                } catch (err) {
                    showPortAliasStatus(`儲存失敗: ${err.message}`, 'error');
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
            if (!confirm(`您確定要刪除 Port ${item.port} 的別名嗎？`)) return;
            
            try {
                const res = await fetch(`/api/ports/aliases/${item.port}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                showPortAliasStatus('別名已成功刪除', 'success');
                fetchPortAliases();
                fetchFlows();
            } catch (err) {
                showPortAliasStatus(`刪除失敗: ${err.message}`, 'error');
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
        showPortAliasStatus('請填寫 Port 埠號與別名名稱。', 'error');
        return;
    }

    try {
        const res = await fetch(`/api/ports/aliases?port=${port}&name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('Failed to save port alias');
        
        showPortAliasStatus(`已成功將 Port ${port} 對應為 ${name}`, 'success');
        inputPort.value = '';
        inputName.value = '';
        fetchPortAliases();
        // Refresh flows table to reflect names update immediately
        fetchFlows();
    } catch (err) {
        showPortAliasStatus(`儲存失敗: ${err.message}`, 'error');
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
            <td colspan="3" class="text-center text-muted py-3">正在載入 IP 別名...</td>
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
        const signal = getAbortSignal('ipAliases');
        const res = await fetch(url, { signal });
        if (!res.ok) throw new Error('Failed to fetch IP aliases');
        const data = await res.json();
        
        state.ipAliasesPagination.total = data.total;
        
        renderIpAliasesTable(data.records);
        renderIpAliasesPagination(data.total);
    } catch (err) {
        if (err.name === 'AbortError') return;
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
                <td colspan="3" class="text-center text-muted py-3">尚未設定任何自訂 IP 別名。</td>
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
                    showIpAliasStatus('別名名稱不得為空', 'error');
                    return;
                }
                
                try {
                    const res = await fetch(`/api/ips/aliases?ip=${encodeURIComponent(item.ip)}&name=${encodeURIComponent(newName)}`, { method: 'POST' });
                    if (!res.ok) throw new Error('Save request failed');
                    showIpAliasStatus('IP 別名已成功更新', 'success');
                    fetchIpAliases();
                    fetchFlows();
                } catch (err) {
                    showIpAliasStatus(`儲存失敗: ${err.message}`, 'error');
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
            if (!confirm(`您確定要刪除 IP ${item.ip} 的別名嗎？`)) return;
            
            try {
                const res = await fetch(`/api/ips/aliases/${encodeURIComponent(item.ip)}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                showIpAliasStatus('IP 別名已成功刪除', 'success');
                fetchIpAliases();
                fetchFlows();
            } catch (err) {
                showIpAliasStatus(`刪除失敗: ${err.message}`, 'error');
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
        showIpAliasStatus('請填寫 IP 位址與別名名稱。', 'error');
        return;
    }

    try {
        const res = await fetch(`/api/ips/aliases?ip=${encodeURIComponent(ip)}&name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('Failed to save IP alias');
        
        showIpAliasStatus(`已成功將 IP ${ip} 對應為 ${name}`, 'success');
        inputIp.value = '';
        inputName.value = '';
        fetchIpAliases();
        // Refresh flows table to reflect names update immediately
        fetchFlows();
    } catch (err) {
        showIpAliasStatus(`儲存失敗: ${err.message}`, 'error');
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

let currentAuditRules = [];

// Fetch all audit rules
async function fetchAuditRules() {
    try {
        const response = await fetch('/api/audit/rules');
        if (!response.ok) throw new Error('Failed to fetch rules');
        const rules = await response.json();
        currentAuditRules = rules;
        
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
            let ipText = rule.ip || '';
            let showAlias = rule.ip_alias;
            if (ipText.toLowerCase() === 'internal') {
                ipText = 'Private IP';
                showAlias = '';
            } else if (ipText.toLowerCase() === 'external') {
                ipText = 'Public IP';
                showAlias = '';
            }
            const ipAliasSub = showAlias ? `<div class="domain-subtext" style="font-size: 0.75rem; color: var(--text-muted);">${showAlias}</div>` : '';
            const ipDisplay = rule.ip ? `<div>${ipText}</div>${ipAliasSub}` : '<span class="text-muted">(任意)</span>';
            const portAliasSub = rule.port_name ? `<div class="domain-subtext" style="font-size: 0.75rem; color: var(--text-muted);">${rule.port_name}</div>` : '';
            const portDisplay = rule.port ? `<div>${rule.port}</div>${portAliasSub}` : '<span class="text-muted">(任意)</span>';
            const badgeClass = rule.flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
            const flagText = rule.flag === 'watch' ? '關注' : '異常';
            
            return `
                <tr>
                    <td style="padding: 10px 12px; font-family: var(--font-mono);">${ipDisplay}</td>
                    <td style="padding: 10px 12px; font-family: var(--font-mono);">${portDisplay}</td>
                    <td style="padding: 10px 12px; text-align: center;">
                        <span class="badge ${badgeClass}" style="cursor: pointer;" title="點擊編輯規則" onclick="openEditAuditRuleModal(${rule.id})">${flagText}</span>
                    </td>
                    <td style="padding: 10px 12px; text-align: right; white-space: nowrap;">
                        <button class="btn btn-secondary btn-sm" onclick="openEditAuditRuleModal(${rule.id})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; margin-right: 6px;">
                            編輯
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="deleteAuditRule(${rule.id})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">
                            刪除
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            lucide.createIcons();
        }
    } catch (err) {
        console.error('Error fetching audit rules:', err);
    }
}

// Open Edit Audit Rule Modal
function openEditAuditRuleModal(ruleId) {
    const rule = currentAuditRules.find(r => r.id === ruleId);
    if (!rule) return;
    
    if (els.editRuleId) els.editRuleId.value = rule.id;
    if (els.editRuleErrorMessage) {
        els.editRuleErrorMessage.style.display = 'none';
        els.editRuleErrorMessage.innerText = '';
    }
    
    const rawIp = rule.ip || '';
    if (els.editRuleSelectIpType && els.editRuleInputIp) {
        if (!rawIp) {
            els.editRuleSelectIpType.value = '';
            els.editRuleInputIp.style.display = 'none';
            els.editRuleInputIp.value = '';
        } else if (rawIp.toLowerCase() === 'internal') {
            els.editRuleSelectIpType.value = 'internal';
            els.editRuleInputIp.style.display = 'none';
            els.editRuleInputIp.value = '';
        } else if (rawIp.toLowerCase() === 'external') {
            els.editRuleSelectIpType.value = 'external';
            els.editRuleInputIp.style.display = 'none';
            els.editRuleInputIp.value = '';
        } else {
            els.editRuleSelectIpType.value = 'custom';
            els.editRuleInputIp.style.display = 'block';
            els.editRuleInputIp.value = rawIp;
        }
    }
    
    if (els.editRuleInputPort) {
        els.editRuleInputPort.value = rule.port || '';
    }
    
    const flagRadios = document.querySelectorAll('input[name="edit-rule-input-flag"]');
    flagRadios.forEach(radio => {
        radio.checked = (radio.value === rule.flag);
    });
    
    if (els.modalEditAuditRule) {
        els.modalEditAuditRule.classList.add('active');
    }
}

// Close Edit Audit Rule Modal
function closeEditRuleModal() {
    if (els.modalEditAuditRule) {
        els.modalEditAuditRule.classList.remove('active');
    }
    if (els.editRuleErrorMessage) {
        els.editRuleErrorMessage.style.display = 'none';
        els.editRuleErrorMessage.innerText = '';
    }
}

// Show error in Edit Modal
function showEditRuleError(msg) {
    if (els.editRuleErrorMessage) {
        els.editRuleErrorMessage.innerText = msg;
        els.editRuleErrorMessage.style.display = 'block';
    }
}

// Submit edited rule with duplicate check
async function submitEditAuditRule(e) {
    if (e) e.preventDefault();
    if (!els.editRuleId) return;
    const ruleId = parseInt(els.editRuleId.value, 10);
    if (!ruleId) return;
    
    let ip = '';
    if (els.editRuleSelectIpType) {
        const type = els.editRuleSelectIpType.value;
        if (type === 'custom') {
            ip = els.editRuleInputIp ? els.editRuleInputIp.value.trim() : '';
            if (!ip) {
                showEditRuleError('請輸入自訂 IP 或 CIDR！');
                return;
            }
        } else {
            ip = type;
        }
    }
    
    const port = els.editRuleInputPort ? els.editRuleInputPort.value.trim() : '';
    const flagEl = document.querySelector('input[name="edit-rule-input-flag"]:checked');
    const flag = flagEl ? flagEl.value : 'watch';
    
    if (!ip && !port) {
        showEditRuleError('IP 與 Port 不能同時為空！');
        return;
    }
    
    // Duplicate check against current rules (excluding self)
    const normalizedNewIp = ip ? ip.toLowerCase() : '';
    const normalizedNewPort = port || '';
    const isDuplicate = currentAuditRules.some(r => {
        if (r.id === ruleId) return false;
        const existingIp = (r.ip || '').toLowerCase();
        const existingPort = r.port || '';
        return existingIp === normalizedNewIp && existingPort === normalizedNewPort;
    });
    
    if (isDuplicate) {
        showEditRuleError('已存在相同 IP/CIDR 與 Port 的比對規則，無法重複儲存！');
        return;
    }
    
    try {
        const response = await fetch(`/api/audit/rules/${ruleId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip || null, port: port || null, flag })
        });
        
        const data = await response.json();
        if (response.ok) {
            closeEditRuleModal();
            showAuditRuleStatus('規則已成功更新！', 'success');
            fetchAuditRules();
        } else {
            showEditRuleError(data.detail || '更新失敗');
        }
    } catch (err) {
        showEditRuleError(`連線錯誤: ${err.message}`);
    }
}

// Submit new rule with duplicate check
async function submitAuditRule() {
    const ipSelect = document.getElementById('audit-select-ip-type');
    let ip = '';
    if (ipSelect) {
        const type = ipSelect.value;
        if (type === 'custom') {
            ip = els.auditInputIp.value.trim();
        } else {
            ip = type;
        }
    } else {
        ip = els.auditInputIp.value.trim();
    }
    const port = els.auditInputPort.value.trim();
    
    const flagEl = document.querySelector('input[name="audit-input-flag"]:checked');
    const flag = flagEl ? flagEl.value : 'watch';
    
    if (!ip && !port) {
        showAuditRuleStatus('IP 與 Port 不能同時為空！', 'error');
        return;
    }
    
    // Duplicate check against current rules
    const normalizedNewIp = ip ? ip.toLowerCase() : '';
    const normalizedNewPort = port || '';
    const isDuplicate = currentAuditRules.some(r => {
        const existingIp = (r.ip || '').toLowerCase();
        const existingPort = r.port || '';
        return existingIp === normalizedNewIp && existingPort === normalizedNewPort;
    });
    
    if (isDuplicate) {
        showAuditRuleStatus('已存在相同 IP/CIDR 與 Port 的比對規則，無法重複新增！', 'error');
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
            if (ipSelect) {
                ipSelect.value = '';
                els.auditInputIp.style.display = 'none';
            }
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

// Make functions globally available
window.openEditAuditRuleModal = openEditAuditRuleModal;
window.closeEditRuleModal = closeEditRuleModal;
window.submitEditAuditRule = submitEditAuditRule;
window.deleteAuditRule = deleteAuditRule;

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
        const signal = getAbortSignal('auditMatches');
        const response = await fetch(url, { signal });
        if (!response.ok) throw new Error('Failed to fetch matched records');
        const data = await response.json();
        
        state.auditRecords = data.records; // Cache rules records in state
        state.auditPagination.total = data.total;
        els.auditTotalFiltered.innerText = data.total;
        
        renderAuditMatches(data.records);
        renderAuditPagination(data.total);
    } catch (err) {
        if (err.name === 'AbortError') return;
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
                <td colspan="11" class="text-center text-muted py-5">無任何比對符合的流量存檔資料</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = records.map((r, idx) => {
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注' : '異常';
        
        const exporterSub = r.exporter_alias ? `<div class="domain-subtext" title="${r.exporter_alias}">${r.exporter_alias}</div>` : '';
        const srcDomainSub = r.src_domain ? `<div class="domain-subtext">${r.src_domain}</div>` : '';
        const dstDomainSub = r.dst_domain ? `<div class="domain-subtext">${r.dst_domain}</div>` : '';
        const sportAliasSub = r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : '';
        const dportAliasSub = r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : '';
        
        return `
            <tr class="flow-row" onclick="showAuditFlowDetails(${idx})">
                <td style="padding: 10px 12px; font-family: var(--font-mono);">${r.ts}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <span class="badge ${badgeClass}">${flagText}</span>
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.exporter || 'N/A'}</div>
                    ${exporterSub}
                </td>
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
    
    // Display Matched Rule Section
    if (els.detailRuleSection) {
        els.detailRuleSection.style.display = 'block';
        
        let ruleIpDisplay = '(任意)';
        if (r.rule_ip) {
            const lowerIp = r.rule_ip.toLowerCase();
            ruleIpDisplay = lowerIp === 'internal' ? 'Private IP' : (lowerIp === 'external' ? 'Public IP' : r.rule_ip);
            if (r.rule_ip_alias && lowerIp !== 'internal' && lowerIp !== 'external') {
                ruleIpDisplay += ` (${r.rule_ip_alias})`;
            }
        }
        els.detailRuleIp.innerText = ruleIpDisplay;
        els.detailRulePort.innerText = r.rule_port || '(任意)';
        
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注 (Watch)' : '異常 (Anomaly)';
        els.detailMatchFlag.className = `badge ${badgeClass}`;
        els.detailMatchFlag.innerText = flagText;
        
        els.detailMatchTs.innerText = r.match_ts ? formatSqlTimestamp(r.match_ts) : 'N/A';
    }
    
    els.detailId.innerText = r.id || 'N/A';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : 'N/A';
    els.detailType.innerText = r.proto ? r.proto.toUpperCase() : 'N/A';
    els.detailType.className = `value badge ${r.proto === 'ipfix' ? 'badge-info' : (r.proto === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    const exporterAlias = r.exporter_alias ? ` (${r.exporter_alias})` : '';
    els.detailExporter.innerText = `${r.exporter || 'N/A'}${exporterAlias}`;
    els.detailSrc.innerText = r.src || 'N/A';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || 'N/A';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || r.proto || 'N/A';
    els.detailOctets.innerText = `${formatNumber(r.octets)} 位元組 (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Parse json_data
    let raw = {};
    if (r.json_data) {
        try {
            raw = JSON.parse(r.json_data);
        } catch (e) {
            raw = { error: "解析 json_data 失敗", raw: r.json_data };
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
    if (state.anomaliesFilters.ip) url += `&ip=${encodeURIComponent(state.anomaliesFilters.ip)}`;
    if (state.anomaliesFilters.src) url += `&src=${encodeURIComponent(state.anomaliesFilters.src)}`;
    if (state.anomaliesFilters.dst) url += `&dst=${encodeURIComponent(state.anomaliesFilters.dst)}`;
    if (state.anomaliesFilters.port) url += `&port=${encodeURIComponent(state.anomaliesFilters.port)}`;
    if (state.anomaliesFilters.sport) url += `&sport=${encodeURIComponent(state.anomaliesFilters.sport)}`;
    if (state.anomaliesFilters.dport) url += `&dport=${encodeURIComponent(state.anomaliesFilters.dport)}`;
    if (state.anomaliesFilters.proto) url += `&proto=${encodeURIComponent(state.anomaliesFilters.proto)}`;
    if (state.anomaliesFilters.flag) url += `&flag=${encodeURIComponent(state.anomaliesFilters.flag)}`;
    
    // Dynamic multi-conditions
    if (state.anomaliesFilters.conditions && state.anomaliesFilters.conditions.length > 0) {
        const validConds = state.anomaliesFilters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            url += `&conditions=${encodeURIComponent(JSON.stringify(validConds))}&logic=${encodeURIComponent(state.anomaliesFilters.logic || 'AND')}`;
        }
    }
    
    try {
        const signal = getAbortSignal('anomaliesReport');
        const response = await fetch(url, { signal });
        if (!response.ok) throw new Error('Failed to fetch anomalous records');
        const data = await response.json();
        
        state.anomaliesRecords = data.records; // Cache in state
        state.anomaliesPagination.total = data.total;
        els.anomaliesTotalFiltered.innerText = data.total;
        
        renderAnomalousReportTable(data.records);
        renderAnomaliesPagination(data.total);
        fetchAnomalousReportStats();
    } catch (err) {
        if (err.name === 'AbortError') return;
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
                <td colspan="10" class="text-center text-muted py-5">無任何異常流量報告資料</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = records.map((r, idx) => {
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注' : '異常';
        
        const exporterSub = r.exporter_alias ? `<div class="domain-subtext" title="${r.exporter_alias}">${r.exporter_alias}</div>` : '';
        const srcDomainSub = r.src_domain ? `<div class="domain-subtext">${r.src_domain}</div>` : '';
        const dstDomainSub = r.dst_domain ? `<div class="domain-subtext">${r.dst_domain}</div>` : '';
        const sportAliasSub = r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : '';
        const dportAliasSub = r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : '';
        
        return `
            <tr class="flow-row" onclick="showAnomaliesFlowDetails(${idx})">
                <td style="padding: 10px 12px; font-family: var(--font-mono);">${r.ts}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <span class="badge ${badgeClass}">${flagText}</span>
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.exporter || 'N/A'}</div>
                    ${exporterSub}
                </td>
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
    
    // Display Matched Rule Section
    if (els.detailRuleSection) {
        els.detailRuleSection.style.display = 'block';
        
        let ruleIpDisplay = '(任意)';
        if (r.rule_ip) {
            const lowerIp = r.rule_ip.toLowerCase();
            ruleIpDisplay = lowerIp === 'internal' ? 'Private IP' : (lowerIp === 'external' ? 'Public IP' : r.rule_ip);
            if (r.rule_ip_alias && lowerIp !== 'internal' && lowerIp !== 'external') {
                ruleIpDisplay += ` (${r.rule_ip_alias})`;
            }
        }
        els.detailRuleIp.innerText = ruleIpDisplay;
        els.detailRulePort.innerText = r.rule_port || '(任意)';
        
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注 (Watch)' : '異常 (Anomaly)';
        els.detailMatchFlag.className = `badge ${badgeClass}`;
        els.detailMatchFlag.innerText = flagText;
        
        els.detailMatchTs.innerText = r.match_ts ? formatSqlTimestamp(r.match_ts) : 'N/A';
    }
    
    els.detailId.innerText = r.id || 'N/A';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : 'N/A';
    els.detailType.innerText = r.proto ? r.proto.toUpperCase() : 'N/A';
    els.detailType.className = `value badge ${r.proto === 'ipfix' ? 'badge-info' : (r.proto === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    const exporterAlias = r.exporter_alias ? ` (${r.exporter_alias})` : '';
    els.detailExporter.innerText = `${r.exporter || 'N/A'}${exporterAlias}`;
    els.detailSrc.innerText = r.src || 'N/A';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || 'N/A';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || r.proto || 'N/A';
    els.detailOctets.innerText = `${formatNumber(r.octets)} 位元組 (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Parse json_data
    let raw = {};
    if (r.json_data) {
        try {
            raw = JSON.parse(r.json_data);
        } catch (e) {
            raw = { error: "解析 json_data 失敗", raw: r.json_data };
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
    if (state.anomaliesFilters.ip) url += `&ip=${encodeURIComponent(state.anomaliesFilters.ip)}`;
    if (state.anomaliesFilters.src) url += `&src=${encodeURIComponent(state.anomaliesFilters.src)}`;
    if (state.anomaliesFilters.dst) url += `&dst=${encodeURIComponent(state.anomaliesFilters.dst)}`;
    if (state.anomaliesFilters.port) url += `&port=${encodeURIComponent(state.anomaliesFilters.port)}`;
    if (state.anomaliesFilters.sport) url += `&sport=${encodeURIComponent(state.anomaliesFilters.sport)}`;
    if (state.anomaliesFilters.dport) url += `&dport=${encodeURIComponent(state.anomaliesFilters.dport)}`;
    if (state.anomaliesFilters.proto) url += `&proto=${encodeURIComponent(state.anomaliesFilters.proto)}`;
    if (state.anomaliesFilters.flag) url += `&flag=${encodeURIComponent(state.anomaliesFilters.flag)}`;

    // Dynamic multi-conditions
    if (state.anomaliesFilters.conditions && state.anomaliesFilters.conditions.length > 0) {
        const validConds = state.anomaliesFilters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            url += `&conditions=${encodeURIComponent(JSON.stringify(validConds))}&logic=${encodeURIComponent(state.anomaliesFilters.logic || 'AND')}`;
        }
    }

    try {
        const signal = getAbortSignal('anomaliesStats');
        const response = await fetch(url, { signal });
        if (!response.ok) throw new Error('Failed to fetch stats');
        const data = await response.json();

        // Render Top Sources chart
        renderAnomaliesBarChart(
            'chart-anomalies-sources',
            data.top_sources.map(x => formatChartIPLabel(x.src, x.domain)),
            data.top_sources.map(x => x.bytes),
            '來源流量 (Bytes)',
            'rgba(245, 158, 11, 0.7)',
            'rgba(245, 158, 11, 1)',
            { itemType: 'ip', defaultDir: 'src', viewType: 'anomalies', rawItems: data.top_sources.map(x => x.src) }
        );

        // Render Top Destinations chart
        renderAnomaliesBarChart(
            'chart-anomalies-destinations',
            data.top_destinations.map(x => formatChartIPLabel(x.dst, x.domain)),
            data.top_destinations.map(x => x.bytes),
            '目的流量 (Bytes)',
            'rgba(16, 185, 129, 0.7)',
            'rgba(16, 185, 129, 1)',
            { itemType: 'ip', defaultDir: 'dst', viewType: 'anomalies', rawItems: data.top_destinations.map(x => x.dst) }
        );

        // Render Top Ports chart
        renderAnomaliesBarChart(
            'chart-anomalies-ports',
            data.top_ports.map(x => x.port.toString() + (x.port_name ? ` (${x.port_name})` : '')),
            data.top_ports.map(x => x.bytes),
            '連接埠流量 (Bytes)',
            'rgba(99, 102, 241, 0.7)',
            'rgba(99, 102, 241, 1)',
            { itemType: 'port', defaultDir: 'any', viewType: 'anomalies', rawItems: data.top_ports.map(x => x.port) }
        );

        // Render Top Anomalous IP Aliases chart
        const topAnomaliesAliases = data.top_aliases || [];
        renderAnomaliesBarChart(
            'chart-anomalies-aliases',
            topAnomaliesAliases.map(x => formatChartAliasLabel(x.name)),
            topAnomaliesAliases.map(x => x.bytes),
            '別名流量 (Bytes)',
            'rgba(236, 72, 153, 0.7)',
            'rgba(236, 72, 153, 1)',
            { 
                itemType: 'alias', 
                defaultDir: 'any', 
                viewType: 'anomalies', 
                rawItems: topAnomaliesAliases.map(x => x.name),
                flowCounts: topAnomaliesAliases.map(x => x.flows)
            }
        );
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Error fetching anomalous report stats:', err);
    }
}

// Render Anomalous Bar Chart helper
function renderAnomaliesBarChart(canvasId, labels, data, label, bgColor, borderColor, drillMeta) {
    destroyChart(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    const ds = {
        label: label,
        data: data,
        backgroundColor: bgColor,
        borderColor: borderColor,
        borderWidth: 1,
        borderRadius: 4
    };
    if (drillMeta) {
        ds.drillMeta = drillMeta;
    }

    state.charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [ds]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (event, elements, chart) => {
                if (!elements || elements.length === 0) return;
                const index = elements[0].index;
                const meta = chart.data.datasets[0].drillMeta;
                if (!meta) return;
                const rawVal = (meta.rawItems && meta.rawItems[index] !== undefined) ? meta.rawItems[index] : chart.data.labels[index];
                showChartContextMenu(event.native || event, meta.itemType, rawVal, meta.viewType, meta.defaultDir);
            },
            onHover: (event, chartElement) => {
                const target = event.native ? event.native.target : (event.target || (event.chart && event.chart.canvas));
                if (target) {
                    target.style.cursor = chartElement[0] ? 'pointer' : 'default';
                }
            },
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
                        title: function(context) {
                            if (!context || !context.length) return '';
                            const meta = context[0].chart.data.datasets[0].drillMeta;
                            if (meta && meta.itemType === 'alias' && meta.rawItems && meta.rawItems[context[0].dataIndex] !== undefined) {
                                return meta.rawItems[context[0].dataIndex];
                            }
                            return context[0].label;
                        },
                        label: function(context) {
                            let label = ` ${context.dataset.label}: ${formatBytes(context.parsed.y)}`;
                            const meta = context.chart.data.datasets[0].drillMeta;
                            if (meta && meta.flowCounts && meta.flowCounts[context.dataIndex] !== undefined) {
                                label += ` (${formatNumber(meta.flowCounts[context.dataIndex])} flows)`;
                            }
                            return label;
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
                        maxRotation: 45,
                        minRotation: 0,
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

// Dynamic Condition Utilities
let _conditionIdCounter = 0;
function genConditionId() {
    return 'cond_' + Date.now() + '_' + (++_conditionIdCounter);
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Render dynamic conditions list for 'flow' or 'anomalies'
function renderConditions(viewType) {
    const isFlow = (viewType === 'flow');
    const container = isFlow ? document.getElementById('flow-conditions-list') : document.getElementById('anomalies-conditions-list');
    if (!container) return;

    const conditions = isFlow ? (state.filters.conditions || []) : (state.anomaliesFilters.conditions || []);
    const logic = isFlow ? (state.filters.logic || 'AND') : (state.anomaliesFilters.logic || 'AND');

    // Update active logic buttons in UI
    const logicBtns = document.querySelectorAll(`.btn-logic[data-view="${isFlow ? 'flow' : 'anomalies'}"]`);
    logicBtns.forEach(btn => {
        if (btn.getAttribute('data-logic') === logic) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    if (conditions.length === 0) {
        container.innerHTML = `
            <div class="conditions-empty-tip">
                <i data-lucide="info" style="width: 14px; height: 14px; display: inline-block; vertical-align: -2px; margin-right: 4px;"></i>
                尚未新增任何條件 (可點擊「＋ 新增條件」或直接點擊上方/下方圖表項目以追加為篩選條件)
            </div>
        `;
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
        }
        return;
    }

    let html = '';
    conditions.forEach((cond, idx) => {
        const badgeLabel = (idx === 0) ? '條件 1' : logic;
        const badgeStyle = (idx === 0) ? 'background: rgba(255,255,255,0.08); color: var(--text-secondary);' : '';
        const isIp = ['src_ip', 'dst_ip', 'any_ip'].includes(cond.field);
        const isAlias = ['ip_alias', 'src_alias', 'dst_alias'].includes(cond.field);
        const isPort = ['src_port', 'dst_port', 'any_port'].includes(cond.field);
        const isProto = cond.field === 'proto';

        html += `
            <div class="condition-row" data-id="${cond.id || ''}" data-index="${idx}">
                <span class="condition-badge-logic" style="${badgeStyle}">${badgeLabel}</span>
                <select class="condition-select cond-field" data-index="${idx}">
                    <option value="src_ip" ${cond.field === 'src_ip' ? 'selected' : ''}>來源 IP</option>
                    <option value="dst_ip" ${cond.field === 'dst_ip' ? 'selected' : ''}>目的 IP</option>
                    <option value="any_ip" ${cond.field === 'any_ip' ? 'selected' : ''}>任一端 IP</option>
                    <option value="ip_alias" ${cond.field === 'ip_alias' ? 'selected' : ''}>IP 別名 (任一端)</option>
                    <option value="src_alias" ${cond.field === 'src_alias' ? 'selected' : ''}>來源 IP 別名</option>
                    <option value="dst_alias" ${cond.field === 'dst_alias' ? 'selected' : ''}>目的 IP 別名</option>
                    <option value="src_port" ${cond.field === 'src_port' ? 'selected' : ''}>來源 Port</option>
                    <option value="dst_port" ${cond.field === 'dst_port' ? 'selected' : ''}>目的 Port</option>
                    <option value="any_port" ${cond.field === 'any_port' ? 'selected' : ''}>任一端 Port</option>
                    <option value="proto" ${cond.field === 'proto' ? 'selected' : ''}>通訊協定</option>
                </select>
                <select class="condition-select cond-iptype" data-index="${idx}" style="display: ${isIp ? 'inline-block' : 'none'};">
                    <option value="custom" ${cond.ipType === 'custom' ? 'selected' : ''}>自訂 IP / 前綴</option>
                    <option value="internal" ${cond.ipType === 'internal' ? 'selected' : ''}>私有 IP (Private)</option>
                    <option value="external" ${cond.ipType === 'external' ? 'selected' : ''}>公網 IP (Public)</option>
                </select>
                <input type="${isPort ? 'number' : 'text'}" 
                       class="condition-input cond-val" 
                       data-index="${idx}" 
                       placeholder="${isIp ? '例如: 192.168.1.1 或 10.0.0.0/8' : (isAlias ? '例如: Cloudflare, Core-Router' : (isPort ? '例如: 80, 443' : '例如: TCP 或 6'))}" 
                       value="${escapeHtml(cond.val || '')}" 
                       style="display: ${isIp && cond.ipType !== 'custom' ? 'none' : 'block'};">
                <button type="button" class="btn-remove-condition" data-index="${idx}" title="移除此條件">
                    <i data-lucide="x" style="width: 15px; height: 15px;"></i>
                </button>
            </div>
        `;
    });

    container.innerHTML = html;
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }

    const getTargetList = () => isFlow ? state.filters.conditions : state.anomaliesFilters.conditions;

    // Attach row events
    container.querySelectorAll('.cond-field').forEach(sel => {
        sel.addEventListener('change', (e) => {
            const idx = parseInt(e.target.getAttribute('data-index'));
            const field = e.target.value;
            const targetList = getTargetList();
            const targetCond = targetList ? targetList[idx] : null;
            if (targetCond) {
                targetCond.field = field;
                if (['src_ip', 'dst_ip', 'any_ip'].includes(field)) {
                    if (!targetCond.ipType) targetCond.ipType = 'custom';
                }
                renderConditions(viewType);
            }
        });
    });

    container.querySelectorAll('.cond-iptype').forEach(sel => {
        sel.addEventListener('change', (e) => {
            const idx = parseInt(e.target.getAttribute('data-index'));
            const ipType = e.target.value;
            const targetList = getTargetList();
            const targetCond = targetList ? targetList[idx] : null;
            if (targetCond) {
                targetCond.ipType = ipType;
                if (ipType !== 'custom') {
                    targetCond.val = ipType;
                } else if (targetCond.val === 'internal' || targetCond.val === 'external') {
                    targetCond.val = '';
                }
                renderConditions(viewType);
            }
        });
    });

    container.querySelectorAll('.cond-val').forEach(inp => {
        inp.addEventListener('input', (e) => {
            const idx = parseInt(e.target.getAttribute('data-index'));
            const targetList = getTargetList();
            const targetCond = targetList ? targetList[idx] : null;
            if (targetCond) {
                targetCond.val = e.target.value;
            }
        });
        inp.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (isFlow) {
                    applyFiltersFromForm();
                    renderConditions('flow');
                    state.pagination.offset = 0;
                    refreshData();
                } else {
                    applyAnomaliesFiltersFromForm();
                    renderConditions('anomalies');
                    state.anomaliesPagination.offset = 0;
                    fetchAnomalousReport();
                }
            }
        });
    });

    container.querySelectorAll('.btn-remove-condition').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const idx = parseInt(btn.getAttribute('data-index'));
            const targetList = getTargetList();
            if (targetList && targetList[idx] !== undefined) {
                targetList.splice(idx, 1);
            }
            renderConditions(viewType);
            if (isFlow) {
                applyFiltersFromForm();
                state.pagination.offset = 0;
                refreshData();
            } else {
                applyAnomaliesFiltersFromForm();
                state.anomaliesPagination.offset = 0;
                fetchAnomalousReport();
            }
        });
    });
}

// Add a new dynamic condition
function addCondition(viewType, field = 'src_ip', val = '', ipType = 'custom') {
    const isFlow = (viewType === 'flow');
    if (isFlow) {
        applyFiltersFromForm();
        if (!state.filters.conditions) state.filters.conditions = [];
        state.filters.conditions.push({
            id: genConditionId(),
            field: field,
            ipType: ['src_ip', 'dst_ip', 'any_ip'].includes(field) ? (ipType || 'custom') : '',
            val: String(val || '')
        });
    } else {
        applyAnomaliesFiltersFromForm();
        if (!state.anomaliesFilters.conditions) state.anomaliesFilters.conditions = [];
        state.anomaliesFilters.conditions.push({
            id: genConditionId(),
            field: field,
            ipType: ['src_ip', 'dst_ip', 'any_ip'].includes(field) ? (ipType || 'custom') : '',
            val: String(val || '')
        });
    }
    renderConditions(viewType);
    
    // Focus last input
    setTimeout(() => {
        const container = isFlow ? document.getElementById('flow-conditions-list') : document.getElementById('anomalies-conditions-list');
        if (container) {
            const inputs = container.querySelectorAll('.cond-val');
            if (inputs.length > 0) {
                inputs[inputs.length - 1].focus();
            }
        }
    }, 50);
}

// Setup Condition Builders controls
function setupConditionBuilders() {
    document.querySelectorAll('.btn-logic').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const view = btn.getAttribute('data-view');
            const logic = btn.getAttribute('data-logic') || 'AND';
            if (view === 'flow') {
                state.filters.logic = logic;
                renderConditions('flow');
                applyFiltersFromForm();
                state.pagination.offset = 0;
                refreshData();
            } else {
                state.anomaliesFilters.logic = logic;
                renderConditions('anomalies');
                applyAnomaliesFiltersFromForm();
                state.anomaliesPagination.offset = 0;
                fetchAnomalousReport();
            }
        });
    });

    const btnAddFlow = document.getElementById('btn-add-flow-condition');
    if (btnAddFlow) {
        btnAddFlow.addEventListener('click', (e) => {
            e.preventDefault();
            addCondition('flow', 'src_ip', '', 'custom');
        });
    }

    const btnAddAnomalies = document.getElementById('btn-add-anomalies-condition');
    if (btnAddAnomalies) {
        btnAddAnomalies.addEventListener('click', (e) => {
            e.preventDefault();
            addCondition('anomalies', 'src_ip', '', 'custom');
        });
    }
}

// Chart Context Menu Handlers
function showChartContextMenu(nativeEvent, itemType, rawVal, viewType, defaultDir) {
    let menu = document.getElementById('chart-context-menu');
    if (!menu) {
        menu = document.createElement('div');
        menu.id = 'chart-context-menu';
        menu.className = 'chart-context-menu';
        document.body.appendChild(menu);
    }

    let html = '';
    if (itemType === 'ip') {
        const primaryDir = defaultDir || 'any';
        const secDir = primaryDir === 'src' ? 'dst' : (primaryDir === 'dst' ? 'src' : 'any');
        html += `
            <div class="chart-context-menu-item" data-action="filter-ip" data-dir="${primaryDir}" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為${primaryDir === 'src' ? '來源 IP' : (primaryDir === 'dst' ? '目的 IP' : '任一端 IP')} (${rawVal})</span>
            </div>
            ${secDir !== primaryDir ? `
            <div class="chart-context-menu-item" data-action="filter-ip" data-dir="${secDir}" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為${secDir === 'src' ? '來源 IP' : '目的 IP'} (${rawVal})</span>
            </div>
            ` : ''}
            <div class="chart-context-menu-item" data-action="filter-ip" data-dir="any" data-val="${rawVal}">
                <i data-lucide="search"></i> <span>➕ 追加為任一端 IP (${rawVal})</span>
            </div>
        `;
    } else if (itemType === 'port') {
        html += `
            <div class="chart-context-menu-item" data-action="filter-port" data-dir="any" data-val="${rawVal}">
                <i data-lucide="search"></i> <span>➕ 追加為任一端 Port (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-port" data-dir="src" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為來源 Port (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-port" data-dir="dst" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為目的 Port (${rawVal})</span>
            </div>
        `;
    } else if (itemType === 'proto') {
        html += `
            <div class="chart-context-menu-item" data-action="filter-proto" data-dir="any" data-val="${rawVal}">
                <i data-lucide="activity"></i> <span>➕ 追加為通訊協定 (${rawVal})</span>
            </div>
        `;
    } else if (itemType === 'alias') {
        html += `
            <div class="chart-context-menu-item" data-action="filter-alias" data-dir="any" data-val="${rawVal}">
                <i data-lucide="tag"></i> <span>➕ 追加為任一端 IP 別名 (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-alias" data-dir="src" data-val="${rawVal}">
                <i data-lucide="arrow-up-right"></i> <span>➕ 追加為來源 IP 別名 (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-alias" data-dir="dst" data-val="${rawVal}">
                <i data-lucide="arrow-down-left"></i> <span>➕ 追加為目的 IP 別名 (${rawVal})</span>
            </div>
        `;
    }

    menu.innerHTML = html;
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }

    menu.style.display = 'block';
    const x = nativeEvent.clientX || 100;
    const y = nativeEvent.clientY || 100;
    const menuWidth = 270;
    const menuHeight = menu.offsetHeight || 140;

    const posX = (x + menuWidth > window.innerWidth) ? Math.max(10, x - menuWidth) : x;
    const posY = (y + menuHeight > window.innerHeight) ? Math.max(10, y - menuHeight) : y;
    menu.style.left = `${posX}px`;
    menu.style.top = `${posY}px`;

    menu.querySelectorAll('.chart-context-menu-item').forEach(item => {
        item.onclick = (e) => {
            e.stopPropagation();
            const action = item.getAttribute('data-action');
            const dir = item.getAttribute('data-dir');
            const val = item.getAttribute('data-val');
            hideChartContextMenu();
            applyDrillDownFilter(viewType, action, dir, val);
        };
    });
}

function hideChartContextMenu() {
    const menu = document.getElementById('chart-context-menu');
    if (menu) menu.style.display = 'none';
}

function applyDrillDownFilter(viewType, action, dir, val) {
    let field = 'any_ip';
    if (action === 'filter-ip') {
        field = dir === 'src' ? 'src_ip' : (dir === 'dst' ? 'dst_ip' : 'any_ip');
    } else if (action === 'filter-alias') {
        field = dir === 'src' ? 'src_alias' : (dir === 'dst' ? 'dst_alias' : 'ip_alias');
    } else if (action === 'filter-port') {
        field = dir === 'src' ? 'src_port' : (dir === 'dst' ? 'dst_port' : 'any_port');
    } else if (action === 'filter-proto') {
        field = 'proto';
    }

    if (viewType === 'general') {
        addCondition('flow', field, val, 'custom');
        applyFiltersFromForm();
        state.pagination.offset = 0;
        refreshData();
    } else if (viewType === 'anomalies') {
        addCondition('anomalies', field, val, 'custom');
        applyAnomaliesFiltersFromForm();
        state.anomaliesPagination.offset = 0;
        fetchAnomalousReport();
    }
}

// Fetch Collector Ports Settings
async function fetchCollectorSettings() {
    try {
        const res = await fetch('/api/settings/collector');
        if (!res.ok) throw new Error('Failed to fetch collector settings');
        const data = await res.json();
        if (els.inputSettingNetflowPort) els.inputSettingNetflowPort.value = data.netflow_port || 2055;
        if (els.inputSettingIpfixPort) els.inputSettingIpfixPort.value = data.ipfix_port || 4739;
    } catch (err) {
        showCollectorSettingsStatus(`載入設定失敗: ${err.message}`, 'error');
    }
}

// Save Collector Ports Settings
async function saveCollectorSettings() {
    const nfPort = parseInt(els.inputSettingNetflowPort.value);
    const ipfixPort = parseInt(els.inputSettingIpfixPort.value);

    if (isNaN(nfPort) || nfPort < 1 || nfPort > 65535) {
        showCollectorSettingsStatus('NetFlow Port 必須為 1 至 65535 之間的有效數字', 'error');
        return;
    }
    if (isNaN(ipfixPort) || ipfixPort < 1 || ipfixPort > 65535) {
        showCollectorSettingsStatus('IPFIX Port 必須為 1 至 65535 之間的有效數字', 'error');
        return;
    }
    if (nfPort === ipfixPort) {
        showCollectorSettingsStatus('NetFlow Port 與 IPFIX Port 不可設定為相同 Port 號', 'error');
        return;
    }

    try {
        const res = await fetch('/api/settings/collector', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                netflow_port: nfPort,
                ipfix_port: ipfixPort
            })
        });

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || '儲存失敗');
        }

        showCollectorSettingsStatus(`✅ 監聽埠設定已成功更新並完成同步！ (NetFlow v9: UDP ${data.netflow_port}, IPFIX: UDP ${data.ipfix_port})`, 'success');
    } catch (err) {
        showCollectorSettingsStatus(`儲存設定失敗: ${err.message}`, 'error');
    }
}

// Show status message for Collector Settings
function showCollectorSettingsStatus(message, type) {
    const el = els.collectorSettingsStatus;
    if (!el) return;

    el.style.display = 'block';
    el.innerText = message;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
}

// ---------------- Authentication Logic ----------------
async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        if (res.ok && data.authenticated && data.user) {
            state.currentUser = data.user;
            renderCurrentUser(data.user);
            if (els.viewLogin) els.viewLogin.style.display = 'none';
            
            // Check mandatory password change on first login
            if (data.user.must_change_password) {
                if (els.modalMustChangePassword) {
                    els.modalMustChangePassword.classList.add('active');
                }
            }
            return true;
        } else {
            showLoginScreen();
            return false;
        }
    } catch (err) {
        showLoginScreen();
        return false;
    }
}

function showLoginScreen() {
    state.currentUser = null;
    if (els.viewLogin) {
        els.viewLogin.style.display = 'flex';
        if (els.loginUsername) els.loginUsername.focus();
    }
}

function renderCurrentUser(user) {
    if (els.currentUsername) els.currentUsername.innerText = user.username || 'admin';
    if (els.currentUserRole) els.currentUserRole.innerText = user.role === 'admin' ? '系統管理員' : '一般使用者';
    if (els.userAvatarInitial) els.userAvatarInitial.innerText = (user.username || 'A')[0].toUpperCase();
    
    // Control admin-only elements visibility
    if (els.btnTabUsers) {
        els.btnTabUsers.style.display = user.role === 'admin' ? 'flex' : 'none';
    }
}

async function handleLogin() {
    const username = els.loginUsername.value.trim();
    const password = els.loginPassword.value;
    if (!username || !password) {
        showLoginError('請輸入帳號與密碼');
        return;
    }

    els.loginErrorMessage.style.display = 'none';
    els.btnDoLogin.disabled = true;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || '登入失敗');
        }

        state.currentUser = data.user;
        renderCurrentUser(data.user);
        els.loginPassword.value = '';
        els.viewLogin.style.display = 'none';

        if (data.user.must_change_password && els.modalMustChangePassword) {
            els.modalMustChangePassword.classList.add('active');
        } else {
            // Proceed to app
            fetchExporterDropdown();
            fetchPortAliases();
            fetchIpAliases();
            switchTab('anomalies');
        }
    } catch (err) {
        showLoginError(err.message);
    } finally {
        els.btnDoLogin.disabled = false;
    }
}

function showLoginError(msg) {
    if (els.loginErrorMessage) {
        els.loginErrorMessage.innerText = msg;
        els.loginErrorMessage.style.display = 'block';
    }
}

async function handleLogout() {
    if (!confirm('您確定要登出系統嗎？')) return;
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {}
    showLoginScreen();
}

function openChangePwdModal() {
    if (els.modalChangePassword) {
        els.formChangeOwnPassword.reset();
        if (els.changePwdError) els.changePwdError.style.display = 'none';
        els.modalChangePassword.classList.add('active');
    }
}

function closeChangePwdModal() {
    if (els.modalChangePassword) els.modalChangePassword.classList.remove('active');
}

async function submitChangeOwnPassword() {
    const old_password = els.inputCurrentPwd.value;
    const new_password = els.inputNewOwnPwd.value;
    const confirm_pwd = els.inputNewOwnPwdConfirm.value;

    if (new_password !== confirm_pwd) {
        showChangePwdError('兩次輸入的新密碼不一致！');
        return;
    }
    if (new_password.length < 6) {
        showChangePwdError('新密碼長度至少需為 6 個字元！');
        return;
    }

    try {
        const res = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_password, new_password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '修改失敗');
        
        alert('密碼修改成功！');
        closeChangePwdModal();
    } catch (err) {
        showChangePwdError(err.message);
    }
}

function showChangePwdError(msg) {
    if (els.changePwdError) {
        els.changePwdError.innerText = msg;
        els.changePwdError.style.display = 'block';
    }
}

async function submitForceChangePassword() {
    const old_password = els.inputForceOldPwd.value;
    const new_password = els.inputForceNewPwd.value;
    const confirm_pwd = els.inputForceNewPwdConfirm.value;

    if (new_password !== confirm_pwd) {
        showForcePwdError('兩次輸入的新密碼不一致！');
        return;
    }
    if (new_password.length < 6) {
        showForcePwdError('新密碼長度至少需為 6 個字元！');
        return;
    }

    try {
        const res = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_password, new_password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '更新失敗');
        
        alert('密碼已成功設定！歡迎使用 NetFlow Collector 系統。');
        if (els.modalMustChangePassword) {
            els.modalMustChangePassword.classList.remove('active');
        }
        fetchExporterDropdown();
        fetchPortAliases();
        fetchIpAliases();
        switchTab('anomalies');
    } catch (err) {
        showForcePwdError(err.message);
    }
}

function showForcePwdError(msg) {
    if (els.forcePwdError) {
        els.forcePwdError.innerText = msg;
        els.forcePwdError.style.display = 'block';
    }
}

// ---------------- Retention Settings & Schedule Logic ----------------
async function fetchRetentionSettings() {
    try {
        const res = await fetch('/api/settings/retention');
        if (!res.ok) throw new Error('讀取保留設定失敗');
        const data = await res.json();
        
        if (els.inputRetentionDays) els.inputRetentionDays.value = data.retention_days;
        if (els.inputRetentionTime) els.inputRetentionTime.value = data.schedule_time;
        if (els.selectRetentionEnabled) els.selectRetentionEnabled.value = data.enabled ? '1' : '0';
        if (els.retentionLastRunTime) els.retentionLastRunTime.innerText = data.last_run || '尚未執行';
        if (els.retentionNextRunTime) els.retentionNextRunTime.innerText = data.next_run || '-';
        if (els.retentionLastMessage) els.retentionLastMessage.innerText = data.last_message || '-';
        
        if (els.retentionStatusBadge) {
            if (data.enabled) {
                els.retentionStatusBadge.className = 'badge badge-success';
                els.retentionStatusBadge.innerText = '排程監控中';
            } else {
                els.retentionStatusBadge.className = 'badge badge-secondary';
                els.retentionStatusBadge.innerText = '排程已停用';
            }
        }
    } catch (err) {
        showRetentionAlert(`無法載入資料保留政策設定: ${err.message}`, 'error');
    }
}

async function saveRetentionSettings() {
    const retention_days = parseInt(els.inputRetentionDays.value, 10);
    const schedule_time = els.inputRetentionTime.value;
    const enabled = els.selectRetentionEnabled.value === '1';

    if (isNaN(retention_days) || retention_days < 1) {
        showRetentionAlert('保留天數必須大於 0 天', 'error');
        return;
    }

    try {
        const res = await fetch('/api/settings/retention', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ retention_days, schedule_time, enabled })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '儲存失敗');
        
        showRetentionAlert(data.message || '資料保留政策更新成功！', 'success');
        fetchRetentionSettings();
    } catch (err) {
        showRetentionAlert(err.message, 'error');
    }
}

async function runRetentionNow() {
    if (!confirm(`確定要立即觸發定時排程清理作業嗎？系統將立即清除超過保留天數的 Flow 歷史資料。`)) {
        return;
    }

    showRetentionAlert('正在執行排程清理作業...', 'info');
    try {
        const res = await fetch('/api/flows/cleanup/execute-retention', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '執行失敗');

        showRetentionAlert(data.message || '排程清理已成功完成！', 'success');
        fetchRetentionSettings();
    } catch (err) {
        showRetentionAlert(`執行失敗: ${err.message}`, 'error');
    }
}

function showRetentionAlert(msg, type) {
    const el = els.retentionStatusAlert;
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(59, 130, 246, 0.15)';
        el.style.color = '#60a5fa';
        el.style.border = '1px solid rgba(59, 130, 246, 0.3)';
    }
}

// ---------------- Collector Allowed CIDRs Logic ----------------
async function fetchCollectorCidrs() {
    const tbody = els.collectorCidrsTbody;
    if (!tbody) return;

    try {
        const res = await fetch('/api/settings/collector/cidrs');
        if (!res.ok) throw new Error('無法讀取白名單');
        const list = await res.json();

        if (list.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center text-muted" style="padding: 24px 0;">
                        目前未設定白名單（系統預設接收來自所有來源 Exporter 的流量封包）。
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = '';
        list.forEach(item => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-color)';
            tr.innerHTML = `
                <td style="padding: 10px 14px; font-family: var(--font-mono); font-weight: 600; color: #818cf8;">${item.cidr}</td>
                <td style="padding: 10px 14px; color: var(--text-secondary);">${item.description || '-'}</td>
                <td style="padding: 10px 14px; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">${item.created_at || '-'}</td>
                <td style="padding: 10px 14px; text-align: center;">
                    <button class="btn-del-cidr" data-id="${item.id}" data-cidr="${item.cidr}" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 4px 8px; border-radius: 4px;">
                        <i data-lucide="trash-2" style="width: 15px; height: 15px;"></i>
                    </button>
                </td>
            `;
            const btnDel = tr.querySelector('.btn-del-cidr');
            btnDel.addEventListener('click', () => deleteCollectorCidr(item.id, item.cidr));
            tbody.appendChild(tr);
        });

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            lucide.createIcons();
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger" style="padding: 20px 0;">讀取白名單失敗: ${err.message}</td></tr>`;
    }
}

async function addCollectorCidr() {
    const cidr = els.inputNewCollectorCidr.value.trim();
    const description = els.inputNewCollectorCidrDesc.value.trim();
    if (!cidr) return;

    try {
        const res = await fetch('/api/settings/collector/cidrs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cidr, description })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '新增失敗');

        showCollectorCidrStatus(data.message, 'success');
        els.inputNewCollectorCidr.value = '';
        els.inputNewCollectorCidrDesc.value = '';
        fetchCollectorCidrs();
    } catch (err) {
        showCollectorCidrStatus(err.message, 'error');
    }
}

async function deleteCollectorCidr(id, cidr) {
    if (!confirm(`確定要將 '${cidr}' 從收集器允許接收白名單中移除嗎？`)) return;
    try {
        const res = await fetch(`/api/settings/collector/cidrs/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '刪除失敗');

        showCollectorCidrStatus(`已移除白名單網段 '${cidr}'`, 'success');
        fetchCollectorCidrs();
    } catch (err) {
        showCollectorCidrStatus(err.message, 'error');
    }
}

function showCollectorCidrStatus(msg, type) {
    const el = els.collectorCidrsStatus;
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// ---------------- User Management Logic (Admin) ----------------
async function fetchUsersList() {
    const tbody = els.usersTbody;
    if (!tbody) return;

    try {
        const res = await fetch('/api/users');
        if (!res.ok) {
            if (res.status === 403) {
                tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding: 30px 0;">權限不足，僅系統管理員可檢視與管理帳號清單。</td></tr>`;
                return;
            }
            throw new Error('讀取使用者清單失敗');
        }
        const users = await res.json();
        tbody.innerHTML = '';

        users.forEach(u => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-color)';
            
            const roleBadge = u.role === 'admin' 
                ? `<span class="badge badge-primary">系統管理員</span>` 
                : `<span class="badge badge-secondary">一般使用者</span>`;
                
            const statusBadge = u.is_active 
                ? `<span class="badge badge-success">正常啟用</span>` 
                : `<span class="badge badge-warning" style="color: #f87171;">已停用</span>`;
                
            const pwdBadge = u.must_change_password 
                ? `<span class="badge badge-warning">首次登入須修改</span>` 
                : `<span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">已設定</span>`;

            tr.innerHTML = `
                <td style="padding: 12px 14px; font-weight: 600; color: var(--text-primary);">${u.username}</td>
                <td style="padding: 12px 14px;">${roleBadge}</td>
                <td style="padding: 12px 14px;">${statusBadge}</td>
                <td style="padding: 12px 14px;">${pwdBadge}</td>
                <td style="padding: 12px 14px; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">${u.last_login || '從未登入'}</td>
                <td style="padding: 12px 14px; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">${u.created_at || '-'}</td>
                <td style="padding: 12px 14px; text-align: center;">
                    <div style="display: inline-flex; align-items: center; gap: 6px;">
                        <button class="btn-toggle-active" data-id="${u.id}" data-active="${u.is_active}" data-uname="${u.username}" title="${u.is_active ? '停用帳號' : '啟用帳號'}" style="background: none; border: none; cursor: pointer; padding: 4px; border-radius: 4px; color: ${u.is_active ? '#fbbf24' : '#34d399'};">
                            <i data-lucide="${u.is_active ? 'pause-circle' : 'play-circle'}" style="width: 16px; height: 16px;"></i>
                        </button>
                        <button class="btn-reset-user-pwd" data-id="${u.id}" data-uname="${u.username}" title="重設密碼" style="background: none; border: none; cursor: pointer; padding: 4px; border-radius: 4px; color: #818cf8;">
                            <i data-lucide="key" style="width: 16px; height: 16px;"></i>
                        </button>
                        <button class="btn-del-user" data-id="${u.id}" data-uname="${u.username}" title="刪除帳號" style="background: none; border: none; cursor: pointer; padding: 4px; border-radius: 4px; color: #f87171;" ${u.username === 'admin' ? 'disabled style="opacity: 0.3; cursor: not-allowed;"' : ''}>
                            <i data-lucide="trash-2" style="width: 16px; height: 16px;"></i>
                        </button>
                    </div>
                </td>
            `;

            const btnToggle = tr.querySelector('.btn-toggle-active');
            btnToggle.addEventListener('click', () => toggleUserActive(u.id, u.is_active, u.username));

            const btnReset = tr.querySelector('.btn-reset-user-pwd');
            btnReset.addEventListener('click', () => openResetPasswordModal(u.id, u.username));

            const btnDel = tr.querySelector('.btn-del-user');
            if (u.username !== 'admin') {
                btnDel.addEventListener('click', () => deleteUser(u.id, u.username));
            }

            tbody.appendChild(tr);
        });

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            lucide.createIcons();
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger" style="padding: 20px 0;">載入使用者失敗: ${err.message}</td></tr>`;
    }
}

function openAddUserModal() {
    if (els.modalAddUser) {
        els.formAddUser.reset();
        if (els.addUserError) els.addUserError.style.display = 'none';
        els.modalAddUser.classList.add('active');
        if (els.inputNewUserName) els.inputNewUserName.focus();
    }
}

function closeAddUserModal() {
    if (els.modalAddUser) els.modalAddUser.classList.remove('active');
}

async function submitCreateUser() {
    const username = els.inputNewUserName.value.trim();
    const password = els.inputNewUserPassword.value;
    const role = els.selectNewUserRole.value;

    try {
        const res = await fetch('/api/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '建立使用者失敗');

        closeAddUserModal();
        showUserStatusMessage(data.message || `使用者 '${username}' 建立成功`, 'success');
        fetchUsersList();
    } catch (err) {
        if (els.addUserError) {
            els.addUserError.innerText = err.message;
            els.addUserError.style.display = 'block';
        }
    }
}

async function toggleUserActive(userId, currentActive, username) {
    const targetState = !currentActive;
    const actionText = targetState ? '啟用' : '停用';
    if (!confirm(`確定要${actionText}使用者 '${username}' 嗎？`)) return;

    try {
        const res = await fetch(`/api/users/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_active: targetState })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '更新狀態失敗');

        showUserStatusMessage(`已成功${actionText}使用者 '${username}'`, 'success');
        fetchUsersList();
    } catch (err) {
        showUserStatusMessage(err.message, 'error');
    }
}

function openResetPasswordModal(userId, username) {
    if (els.modalResetUserPassword) {
        els.resetTargetUserId.value = userId;
        els.resetTargetUsername.innerText = username;
        els.formResetUserPassword.reset();
        if (els.resetPwdError) els.resetPwdError.style.display = 'none';
        els.modalResetUserPassword.classList.add('active');
        if (els.inputAdminNewPwd) els.inputAdminNewPwd.focus();
    }
}

function closeResetPwdModal() {
    if (els.modalResetUserPassword) els.modalResetUserPassword.classList.remove('active');
}

async function submitResetUserPassword() {
    const userId = els.resetTargetUserId.value;
    const new_password = els.inputAdminNewPwd.value;

    try {
        const res = await fetch(`/api/users/${userId}/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '重設密碼失敗');

        closeResetPwdModal();
        showUserStatusMessage(data.message || '密碼已成功重設', 'success');
        fetchUsersList();
    } catch (err) {
        if (els.resetPwdError) {
            els.resetPwdError.innerText = err.message;
            els.resetPwdError.style.display = 'block';
        }
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`確定要刪除使用者 '${username}' 嗎？此操作將無法復原。`)) return;

    try {
        const res = await fetch(`/api/users/${userId}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '刪除失敗');

        showUserStatusMessage(data.message || `已成功刪除使用者 '${username}'`, 'success');
        fetchUsersList();
    } catch (err) {
        showUserStatusMessage(err.message, 'error');
    }
}

function showUserStatusMessage(msg, type) {
    const el = els.usersStatusMessage;
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}
