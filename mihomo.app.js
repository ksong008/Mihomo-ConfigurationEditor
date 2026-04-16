(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 mihomo.helpers.js');
    }

    const { createApp, ref, computed, watch, onMounted, nextTick, onErrorCaptured } = Vue;
    const {
        parsePorts,
        parseHosts,
        parseMarkValue,
        getListenPort,
        parseLineList,
        parseCommaList,
        DEFAULT_NFT_PRIVATE4,
        DEFAULT_NFT_PRIVATE6,
        DEFAULT_NFT_COMMON_PORTS,
        normalizeNftablesConfig,
        getSanitizedUiStateForSave,
        parseYamlMapText,
        formatYamlMapText,
        splitByComma,
        deepMerge
    } = window.MihomoHelpers;

    if (
        !window.MihomoCore ||
        !window.MihomoCore.createStateModule ||
        !window.MihomoCore.createProvidersModule ||
        !window.MihomoCore.createImportExportModule ||
        !window.MihomoCore.createPersistenceModule ||
        !window.MihomoFeatureModules ||
        !window.MihomoFeatureModules.createDnsModule ||
        !window.MihomoFeatureModules.createTproxyModule ||
        !window.MihomoFeatureModules.createRulesModule ||
        !window.MihomoFeatureModules.createYamlModule
    ) {
        throw new Error('功能模块未加载，请确认先引入 ./core/state.js ./core/providers.js ./core/import-export.js ./core/persistence.js ./modules/dns.js ./modules/tproxy.js ./modules/rules.js ./modules/yaml.js');
    }

    const STORAGE_VERSION = 19;
    const STORAGE_KEY_PREFIX = 'mihomo_web_config';
    const STORAGE_KEY = `${STORAGE_KEY_PREFIX}_v${STORAGE_VERSION}`;
    const STORAGE_BACKUP_KEY = `${STORAGE_KEY}_backup`;
    const RESTORE_LEGACY_STORAGE_KEYS = ['mihomo_web_config_v17'];
    const CLEANUP_STORAGE_KEYS = ['mihomo_web_config_v17', 'mihomo_web_config_v18', 'mihomo_web_config_v18_backup'];

    createApp({
        setup() {
            const crashError = ref(null);
            const clearPersistedStorage = (includeLegacy = true) => {
                const keys = [STORAGE_KEY, STORAGE_BACKUP_KEY];
                if (includeLegacy) keys.push(...CLEANUP_STORAGE_KEYS);

                keys.forEach((key) => {
                    try {
                        localStorage.removeItem(key);
                    } catch (err) {
                        console.warn('清理本地缓存失败:', key, err);
                    }
                });
            };

            onErrorCaptured((err, instance, info) => {
                console.error('UI渲染层捕获到异常，已自动拦截以防止白屏:', err, info);
                crashError.value = `Error: ${err.message}\nInfo: ${info}\nStack: ${err.stack}`;
                return false;
            });

            const forceClearCache = () => {
                clearPersistedStorage();
                location.reload();
            };

            const askConfirm = (msg) => {
                return window.confirm(msg);
            };

            const {
                tabs,
                panels,
                getDefaultUiState,
                getDefaultConfig
            } = window.MihomoCore.createStateModule();
            const currentTab = ref('general');
            const yamlPreviewBox = ref(null);
            const fileInput = ref(null);

            const renderStatus = ref('实时渲染');
            const isLocating = ref(false);
            let scrollTimeout = null;

            const uiState = ref(getDefaultUiState());
            const config = ref(getDefaultConfig());
            const providersList = ref([]);
            const ruleProvidersList = ref([]);
            const defaultConfigSnapshot = JSON.parse(JSON.stringify(config.value));
            const defaultUiStateSnapshot = JSON.parse(JSON.stringify(uiState.value));
            watch(() => uiState.value.useMirrorForPanels, (n) => {
                const p = panels.find(x => x.id === uiState.value.selectedPanel);
                if (p && p.id !== 'custom') config.value['external-ui-url'] = n ? p.mirrorUrl : p.rawUrl;
            });

            watch(() => uiState.value.useMirrorForGeo, (n) => {
                if (n) {
                    config.value.geo.url = {
                        geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
                        geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
                        mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb'
                    };
                } else {
                    config.value.geo.url = {
                        geoip: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat',
                        geosite: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat',
                        mmdb: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/country.mmdb'
                    };
                }
            });

            watch(() => uiState.value.enableNameserverPolicy, (enabled) => {
                if (!enabled && config.value && config.value.dns) {
                    config.value.dns['direct-nameserver-follow-policy'] = false;
                }
            });

            const resetGeoUrls = () => {
                uiState.value.useMirrorForGeo = true;
                config.value.geo.url = {
                    geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
                    geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
                    mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb'
                };
            };

            const dnsModule = window.MihomoFeatureModules.createDnsModule({
                ref,
                computed,
                watch,
                config,
                uiState
            });
            const {
                dnsListenPortInput,
                normalizeDnsListenInput,
                dnsListenPort,
                showHostsEditor,
                usingTransparentProxy,
                dnsHijackEnabled,
                dnsForwardConflict,
                dnsLocalForwardNeedsNon53,
                specifiedPortsContain53,
                dnsPathPreview,
                ensureSafeDnsListenPortForTransparentProxy
            } = dnsModule;

            const tproxyModule = window.MihomoFeatureModules.createTproxyModule({
                watch,
                computed,
                config,
                uiState,
                dnsListenPort,
                ensureSafeDnsListenPortForTransparentProxy
            });
            const {
                handleTproxyToggle,
                handleTunToggle,
                cancelTproxyEnable,
                resolveTproxyConflicts,
                nftMarkIssues,
                sanitizeNftMarks,
                resetNftMarksSafe,
                routingCommands,
                copyCommands,
                nftablesScript,
                copyNftables,
                downloadNftables,
                systemdService,
                installScript,
                copyInstallScript
            } = tproxyModule;

            const scrollToBottom = () => {
                nextTick(() => {
                    const scrollBox = document.getElementById('main-scroll');
                    if (scrollBox) {
                        scrollBox.scrollTo({ top: scrollBox.scrollHeight, behavior: 'smooth' });
                    }
                });
            };

            const addListener = () => {
                config.value.listeners.push({
                    name: `listener-${config.value.listeners.length + 1}`,
                    type: 'mixed',
                    port: 7890,
                    listen: '::',
                    udp: true
                });
            };
            const removeListener = (idx) => {
                config.value.listeners.splice(idx, 1);
            };

            const rulesModule = window.MihomoFeatureModules.createRulesModule({
                ref,
                config,
                uiState,
                scrollToBottom
            });
            const {
                formatConditions,
                addCondition,
                addRule,
                draggedRuleIndex,
                ruleDragOverIndex,
                onRuleDragStart,
                onRuleDragEnter,
                onRuleDrop,
                onRuleDragEnd,
                parseRuleString
            } = rulesModule;

            const parseSingleProxyNode = (px) => {
                if (!px) return null;

                let portVal = px.port;
                if (typeof portVal === 'string' && !portVal.includes('-')) {
                    const num = Number(portVal);
                    if (!isNaN(num)) portVal = num;
                }

                const base = {
                    name: px.name || `Node-${Math.floor(Math.random() * 1000)}`,
                    type: px.type || 'vless',
                    server: px.server || '',
                    port: portVal || 443,
                    udp: px.udp !== false,
                    tfo: px.tfo || false,
                    ip: px.ip || '',
                    'packet-encoding': px['packet-encoding'] || '',
                    uuid: px.uuid || '',
                    flow: px.flow || '',
                    alterId: px.alterId || 0,
                    password: px['auth-str'] || px.psk || px.password || '',
                    username: px.username || '',
                    cipher: px.cipher || 'auto',
                    plugin: px.plugin || '',
                    'plugin-opts': { mode: 'websocket', host: '', path: '/', tls: false, mux: false, password: '', ...(px['plugin-opts'] || {}) },
                    'kcptun-opts': { crypt: 'aes-128-gcm', ...(px['kcptun-opts'] || {}) },
                    protocol: px.protocol || '',
                    'protocol-param': px['protocol-param'] || '',
                    obfs: px.obfs || '',
                    'obfs-param': px['obfs-param'] || '',
                    version: px.version || '4',
                    'public-key': px['public-key'] || '',
                    'private-key': px['private-key'] || '',
                    'pre-shared-key': px['pre-shared-key'] || '',
                    reserved: px.reserved ? (typeof px.reserved === 'object' ? JSON.stringify(px.reserved) : px.reserved) : '',
                    workers: px.workers || 2,
                    mtu: px.mtu || 1420,
                    'wg-dns': px.dns ? (Array.isArray(px.dns) ? px.dns.join(',') : px.dns) : '',
                    up: px.up || '100 Mbps',
                    down: px.down || '100 Mbps',
                    'obfs-password': px['obfs-password'] || '',
                    ports: px.ports || '',
                    'hop-interval': px['hop-interval'] || '',
                    'congestion-controller': px['congestion-controller'] || 'bbr',
                    'udp-relay-mode': px['udp-relay-mode'] || 'native',
                    'reduce-rtt': px['reduce-rtt'] || false,
                    heartbeat: px.heartbeat || '10s',
                    'request-timeout': px['request-timeout'] || '15s',
                    'udp-over-tcp': px['udp-over-tcp'] || false,
                    passphrase: px.passphrase || '',
                    'obfs-host': px['obfs-host'] || '',
                    network: px.network || 'tcp',
                    tls: px.tls || false,
                    'skip-cert-verify': px['skip-cert-verify'] || false,
                    servername: px.servername || '',
                    'client-fingerprint': px['client-fingerprint'] || '',
                    alpn: px.alpn ? (Array.isArray(px.alpn) ? px.alpn.join(',') : px.alpn) : '',
                    reality: !!(px['reality-opts'] && Object.keys(px['reality-opts']).length > 0) || !!px.reality,
                    'reality-opts': { 'public-key': '', 'short-id': '', ...(px['reality-opts'] || {}) },
                    smux: {
                        enabled: !!(px.smux && px.smux.enabled),
                        protocol: px.smux?.protocol || 'h2mux',
                        'max-connections': px.smux?.['max-connections'] || 4,
                        padding: !!(px.smux?.padding)
                    },
                    'ws-opts': {
                        path: px['ws-opts']?.path || '/',
                        headers: { Host: px['ws-opts']?.headers?.Host || '' },
                        'max-early-data': px['ws-opts']?.['max-early-data'] || 0,
                        'early-data-header-name': px['ws-opts']?.['early-data-header-name'] || 'Sec-WebSocket-Protocol'
                    },
                    'grpc-opts': { 'grpc-service-name': px['grpc-opts']?.['grpc-service-name'] || '' },
                    'httpupgrade-opts': { host: px['httpupgrade-opts']?.host || '', path: px['httpupgrade-opts']?.path || '/' },
                    'h2-opts': { host: px['h2-opts']?.host || '', path: px['h2-opts']?.path || '/' },
                    'http-opts': {
                        path: px['http-opts']?.path || '/',
                        host: px['http-opts']?.host || '',
                        headers: { Host: px['http-opts']?.headers?.Host || '' }
                    },
                    'xhttp-opts': {
                        path: px['xhttp-opts']?.path || '/',
                        host: px['xhttp-opts']?.host || '',
                        mode: px['xhttp-opts']?.mode || 'auto'
                    },
                    'idle-session-check-interval': px['idle-session-check-interval'] || '30s',
                    'idle-session-timeout': px['idle-session-timeout'] || '30s',
                    'min-idle-session': px['min-idle-session'] || 0,
                    transport: px.transport || 'TCP',
                    multiplexing: px.multiplexing || 'MULTIPLEXING_OFF',
                    'dialer-proxy': px['dialer-proxy'] || ''
                };

                if (base['h2-opts'] && Array.isArray(base['h2-opts'].host)) base['h2-opts'].host = base['h2-opts'].host.join(',');
                if (base['http-opts']) {
                    if (Array.isArray(base['http-opts'].path)) base['http-opts'].path = base['http-opts'].path.join(',');
                    if (base['http-opts'].headers && base['http-opts'].headers.Host) {
                        base['http-opts'].host = Array.isArray(base['http-opts'].headers.Host)
                            ? base['http-opts'].headers.Host[0]
                            : base['http-opts'].headers.Host;
                    }
                }
                if (px.type === 'tuic' && !base.uuid) base.uuid = px.uuid || '';
                return base;
            };

            const providersModule = window.MihomoCore.createProvidersModule({
                ref,
                watch,
                config,
                uiState,
                providersList,
                ruleProvidersList,
                scrollToBottom,
                parseSingleProxyNode,
                askConfirm
            });
            const {
                pickPanel,
                addManualProxy,
                addGroup,
                removeGroup,
                toggleGroupCollapse,
                collapseAllGroups,
                expandAllGroups,
                ensureGroupCollapseState,
                removeGroupProxyMember,
                getAvailableGroupMembers,
                getOrderedAvailableGroupMembers,
                onInlineGroupMemberDragStart,
                onInlineGroupMemberDragOver,
                onInlineGroupMemberDrop,
                onGroupProxyDragStart,
                onGroupProxyDrop,
                onGroupProxyDragEnd,
                groupProxyDrag,
                getOrderedGroupUseProviders,
                onGroupUseDragStart,
                onGroupUseDragOver,
                onGroupUseDrop,
                onGroupUseDragEnd,
                groupUseDrag,
                onProxyGroupDragStart,
                onProxyGroupDragOver,
                onProxyGroupDrop,
                onProxyGroupDragEnd,
                proxyGroupDrag,
                pruneInvalidGroupProxyMembers,
                pruneInvalidGroupUseMembers,
                injectRegionGroups,
                autoCategorizeProxies,
                addProvider,
                removeProvider,
                addRuleProvider,
                removeRuleProvider,
                toggleRuleProviderCollapse,
                collapseAllRuleProviders,
                expandAllRuleProviders,
                ensureRuleProviderCollapseState,
                onRuleProviderDragStart,
                onRuleProviderDragOver,
                onRuleProviderDrop,
                onRuleProviderDragEnd,
                ruleProviderDrag,
                updateRuleProviderName,
                updateProviderName,
                updateProxyName,
                updateGroupName,
                getRuleProviderUrl,
                clearLists,
                getInlinePayloadPreview
            } = providersModule;

            const yamlModule = window.MihomoFeatureModules.createYamlModule({
                ref,
                config,
                uiState,
                providersList,
                ruleProvidersList,
                parseSingleProxyNode,
                getRuleProviderUrl
            });
            const {
                yamlSections,
                fullYaml,
                buildYaml
            } = yamlModule;

            const safeBuildYaml = (reason = '') => {
                try {
                    buildYaml();
                    crashError.value = null;
                    if (!isLocating.value) renderStatus.value = '实时渲染';
                    return true;
                } catch (e) {
                    console.error('YAML 构建异常:', reason, e);
                    crashError.value = `YAML 构建异常: ${e.message}\nReason: ${reason}\nStack: ${e.stack || ''}`;
                    renderStatus.value = '渲染失败';
                    return false;
                }
            };

            let lastTarget = '';
            const handleFocus = (e) => {
                const el = e.target.closest('[data-yaml-target]');
                if (el) {
                    const keyword = el.getAttribute('data-yaml-target');
                    if (keyword && keyword !== lastTarget) {
                        lastTarget = keyword;
                        locateAndScroll(keyword);
                    }
                }
            };

            const locateAndScroll = (keyword) => {
                if (!yamlPreviewBox.value) return;
                clearTimeout(scrollTimeout);
                isLocating.value = true;
                renderStatus.value = `追踪: ${keyword.trim().slice(0, 15)}...`;

                scrollTimeout = setTimeout(() => {
                    const container = yamlPreviewBox.value;
                    const lines = fullYaml.value.split('\n');
                    const idx = lines.findIndex(l => l.includes(keyword));
                    if (idx !== -1) {
                        const pre = container.querySelector('pre');
                        if (pre) {
                            const scrollHeight = pre.getBoundingClientRect().height;
                            const lineHeight = lines.length > 0 ? (scrollHeight / lines.length) : 0;
                            const targetY = Math.max(0, idx * lineHeight - 60);
                            container.scrollTo({ top: targetY, behavior: 'smooth' });
                        }
                    }
                    setTimeout(() => {
                        isLocating.value = false;
                        renderStatus.value = '实时渲染';
                    }, 1000);
                }, 100);
            };

            watch(currentTab, (newTab) => {
                if (!yamlPreviewBox.value) return;
                lastTarget = '';
                nextTick(() => {
                    setTimeout(() => {
                        const el = document.getElementById('yaml-' + newTab);
                        if (el) {
                            const container = yamlPreviewBox.value;
                            const pre = container.querySelector('pre');
                            if (!pre) return;
                            const topPos = el.offsetTop - pre.offsetTop;
                            container.scrollTo({ top: Math.max(0, topPos - 15), behavior: 'smooth' });
                        }
                    }, 50);
                });
            });

            const importExportModule = window.MihomoCore.createImportExportModule({
                config,
                uiState,
                providersList,
                ruleProvidersList,
                fileInput,
                fullYaml,
                crashError,
                getDefaultConfig,
                safeBuildYaml,
                parseSingleProxyNode,
                formatYamlMapText,
                parseRuleString,
                scrollToBottom,
                ensureGroupCollapseState,
                ensureRuleProviderCollapseState,
                pruneInvalidGroupProxyMembers,
                pruneInvalidGroupUseMembers
            });
            const {
                normalizeImportedConfigData,
                triggerYamlImport,
                handleYamlImport,
                copyYaml,
                downloadYaml,
                downloadYamlWithRename
            } = importExportModule;
            window.MihomoCore.createPersistenceModule({
                watch,
                onMounted,
                config,
                uiState,
                providersList,
                ruleProvidersList,
                isLocating,
                renderStatus,
                getDefaultConfig,
                defaultConfigSnapshot,
                defaultUiStateSnapshot,
                parseSingleProxyNode,
                normalizeImportedConfigData,
                safeBuildYaml,
                injectRegionGroups,
                ensureGroupCollapseState,
                ensureRuleProviderCollapseState,
                sanitizeNftMarks,
                normalizeNftablesConfig,
                getSanitizedUiStateForSave,
                getListenPort,
                deepMerge,
                clearPersistedStorage,
                storageVersion: STORAGE_VERSION,
                storageKey: STORAGE_KEY,
                storageBackupKey: STORAGE_BACKUP_KEY,
                restoreLegacyStorageKeys: RESTORE_LEGACY_STORAGE_KEYS
            });

            return {
                tabs,
                currentTab,
                yamlPreviewBox,
                fileInput,
                uiState,
                config,
                panels,
                providersList,
                ruleProvidersList,
                pickPanel,
                addListener,
                removeListener,
                addProvider,
                removeProvider,
                addRuleProvider,
                removeRuleProvider,
                toggleRuleProviderCollapse,
                collapseAllRuleProviders,
                expandAllRuleProviders,
                onRuleProviderDragStart,
                onRuleProviderDragOver,
                onRuleProviderDrop,
                onRuleProviderDragEnd,
                ruleProviderDrag,
                updateProviderName,
                getRuleProviderUrl,
                addManualProxy,
                addGroup,
                removeGroup,
                updateProxyName,
                updateGroupName,
                toggleGroupCollapse,
                collapseAllGroups,
                expandAllGroups,
                getAvailableGroupMembers,
                getOrderedAvailableGroupMembers,
                getOrderedGroupUseProviders,
                removeGroupProxyMember,
                onGroupProxyDragStart,
                onGroupProxyDrop,
                onGroupProxyDragEnd,
                groupProxyDrag,
                onInlineGroupMemberDragStart,
                onInlineGroupMemberDragOver,
                onInlineGroupMemberDrop,
                groupUseDrag,
                onGroupUseDragStart,
                onGroupUseDragOver,
                onGroupUseDrop,
                onGroupUseDragEnd,
                onProxyGroupDragStart,
                onProxyGroupDragOver,
                onProxyGroupDrop,
                onProxyGroupDragEnd,
                proxyGroupDrag,
                addRule,
                addCondition,
                draggedRuleIndex,
                ruleDragOverIndex,
                onRuleDragStart,
                onRuleDragEnter,
                onRuleDrop,
                onRuleDragEnd,
                getInlinePayloadPreview,
                yamlSections,
                fullYaml,
                copyYaml,
                downloadYaml,
                downloadYamlWithRename,
                clearLists,
                forceClearCache,
                triggerYamlImport,
                handleYamlImport,
                handleFocus,
                isLocating,
                renderStatus,
                injectRegionGroups,
                autoCategorizeProxies,
                handleTproxyToggle,
                handleTunToggle,
                cancelTproxyEnable,
                resolveTproxyConflicts,
                nftMarkIssues,
                sanitizeNftMarks,
                resetNftMarksSafe,
                routingCommands,
                copyCommands,
                nftablesScript,
                copyNftables,
                downloadNftables,
                systemdService,
                installScript,
                copyInstallScript,
                updateRuleProviderName,
                resetGeoUrls,
                formatConditions,
                dnsListenPort,
                dnsListenPortInput,
                normalizeDnsListenInput,
                showHostsEditor,
                usingTransparentProxy,
                dnsHijackEnabled,
                dnsForwardConflict,
                dnsLocalForwardNeedsNon53,
                dnsPathPreview,
                specifiedPortsContain53,
                crashError,
                askConfirm
            };
        }
    }).mount('#app');

})(window);
