(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 mihomo.helpers.js');
    }

    const { createApp, ref, computed, watch, onMounted, nextTick, onErrorCaptured } = Vue;
    const {
        normalizeListenAddress,
        normalizeNftablesConfig,
        getSanitizedUiStateForSave,
        parseYamlObjectText,
        parseYamlSequenceText,
        formatYamlSequenceText,
        formatYamlMapText,
        deepMerge,
        getShadowsocksCipherOptions,
        isSupportedShadowsocksCipher,
        isShadowsocks2022Cipher,
        generateShadowsocksPassword,
        getSuggestedListenerPort,
        normalizeTunnelListenerNetwork,
        TUNNEL_LISTENER_NETWORK_OPTIONS
    } = window.MihomoHelpers;

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.bootstrapApp = function () {

    if (
        !window.MihomoCore ||
        !window.MihomoCore.createStateModule ||
        !window.MihomoCore.createUiRuntimeModule ||
        !window.MihomoCore.createProvidersModule ||
        !window.MihomoCore.createImportExportModule ||
        !window.MihomoCore.createPersistenceModule ||
        !window.MihomoFeatureModules ||
        !window.MihomoFeatureModules.createProxiesModule ||
        !window.MihomoFeatureModules.createValidationModule ||
        !window.MihomoFeatureModules.createDnsModule ||
        !window.MihomoFeatureModules.createTproxyModule ||
        !window.MihomoFeatureModules.createRulesModule ||
        !window.MihomoFeatureModules.createYamlModule
    ) {
        throw new Error('功能模块未加载，请确认先引入 ./core/state.js ./core/ui-runtime.js ./core/providers.js ./core/import-export.js ./core/persistence.js ./modules/proxies.js ./modules/validation.js ./modules/dns.js ./modules/tproxy.js ./modules/rules.js ./modules/yaml.js');
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
            const cacheWarning = ref('');
            const bilingualLabelPattern = /^(.+?)\s*\(([^()]+)\)$/;
            const bilingualSkipTags = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'PRE', 'CODE', 'OPTION']);
            let bilingualLabelObserver = null;
            let bilingualLabelFrame = 0;
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
            const dismissCacheWarning = () => {
                cacheWarning.value = '';
            };
            const createDualLabelNode = (doc, zh, en) => {
                const wrapper = doc.createElement('span');
                wrapper.className = 'dual-label';

                const zhNode = doc.createElement('span');
                zhNode.className = 'dual-label-zh';
                zhNode.textContent = zh;

                const enNode = doc.createElement('span');
                enNode.className = 'dual-label-en';
                enNode.textContent = en;

                wrapper.appendChild(zhNode);
                wrapper.appendChild(enNode);
                return wrapper;
            };
            const shouldTransformBilingualText = (textNode) => {
                if (!textNode || !textNode.parentElement) return false;
                const parent = textNode.parentElement;
                if (bilingualSkipTags.has(parent.tagName)) return false;
                if (parent.closest('pre, code, textarea, option, .dual-label')) return false;

                const text = String(textNode.nodeValue || '');
                const normalized = text.replace(/\s+/g, ' ').trim();
                return bilingualLabelPattern.test(normalized);
            };
            const applyBilingualLabelLayout = (root = document.getElementById('app')) => {
                if (!root) return;

                const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
                const candidates = [];
                let current = walker.nextNode();

                while (current) {
                    if (shouldTransformBilingualText(current)) candidates.push(current);
                    current = walker.nextNode();
                }

                candidates.forEach((textNode) => {
                    const rawText = String(textNode.nodeValue || '');
                    const normalized = rawText.replace(/\s+/g, ' ').trim();
                    const match = normalized.match(bilingualLabelPattern);
                    if (!match || !textNode.parentNode) return;

                    const [, zh, en] = match;
                    const fragment = document.createDocumentFragment();
                    if (/^\s+/.test(rawText)) fragment.appendChild(document.createTextNode(' '));
                    fragment.appendChild(createDualLabelNode(document, zh.trim(), en.trim()));
                    if (/\s+$/.test(rawText)) fragment.appendChild(document.createTextNode(' '));
                    textNode.parentNode.insertBefore(fragment, textNode);
                    textNode.parentNode.removeChild(textNode);
                });
            };
            const scheduleBilingualLabelLayout = () => {
                if (bilingualLabelFrame) window.cancelAnimationFrame(bilingualLabelFrame);
                bilingualLabelFrame = window.requestAnimationFrame(() => {
                    bilingualLabelFrame = 0;
                    applyBilingualLabelLayout();
                });
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
            const fileInput = ref(null);
            const uiRuntimeModule = window.MihomoCore.createUiRuntimeModule({
                ref,
                watch,
                nextTick,
                fullYaml: {
                    get value() {
                        return fullYaml.value;
                    }
                }
            });
            const {
                currentTab,
                yamlPreviewBox,
                renderStatus,
                isLocating,
                handleFocus,
                scrollToBottom
            } = uiRuntimeModule;

            const uiState = ref(getDefaultUiState());
            const config = ref(getDefaultConfig());
            const providersList = ref([]);
            const ruleProvidersList = ref([]);
            const availableSubRuleNames = computed(() => {
                try {
                    const parsed = parseYamlObjectText(uiState.value && uiState.value.subRulesYaml);
                    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
                    return Object.keys(parsed).filter(Boolean);
                } catch (err) {
                    return [];
                }
            });
            const defaultConfigSnapshot = JSON.parse(JSON.stringify(config.value));
            const defaultUiStateSnapshot = JSON.parse(JSON.stringify(uiState.value));
            onMounted(() => {
                nextTick(() => {
                    scheduleBilingualLabelLayout();
                    const root = document.getElementById('app');
                    if (!root) return;

                    bilingualLabelObserver = new MutationObserver(() => {
                        scheduleBilingualLabelLayout();
                    });
                    bilingualLabelObserver.observe(root, {
                        subtree: true,
                        childList: true,
                        characterData: true
                    });
                });
            });
            watch(() => uiState.value.useMirrorForPanels, (n) => {
                const p = panels.find(x => x.id === uiState.value.selectedPanel);
                if (p && p.id !== 'custom') config.value['external-ui-url'] = n ? p.mirrorUrl : p.rawUrl;
            });

            watch(() => uiState.value.useMirrorForGeo, (n) => {
                if (n) {
                    config.value.geo.url = {
                        geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
                        geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
                        mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb',
                        asn: 'https://fastly.jsdelivr.net/gh/xishang0128/geoip@release/GeoLite2-ASN.mmdb'
                    };
                } else {
                    config.value.geo.url = {
                        geoip: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat',
                        geosite: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat',
                        mmdb: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/country.mmdb',
                        asn: 'https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb'
                    };
                }
            });

            watch(() => uiState.value.enableNameserverPolicy, (enabled) => {
                if (!enabled && config.value && config.value.dns) {
                    config.value.dns['direct-nameserver-follow-policy'] = false;
                }
            });
            const hasNameserverPolicyText = computed(() => String(uiState.value?.dnsNameserverPolicy || '').trim().length > 0);
            const hasDirectNameserverEntries = computed(() => parseLineList(uiState.value?.dnsDirectNameservers).length > 0);
            const canUseDirectNameserverFollowPolicy = computed(() => hasNameserverPolicyText.value && hasDirectNameserverEntries.value);

            watch(canUseDirectNameserverFollowPolicy, (enabled) => {
                if (!enabled && config.value && config.value.dns) {
                    config.value.dns['direct-nameserver-follow-policy'] = false;
                }
            });

            const resetGeoUrls = () => {
                uiState.value.useMirrorForGeo = true;
                config.value.geo.url = {
                    geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
                    geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
                    mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb',
                    asn: 'https://fastly.jsdelivr.net/gh/xishang0128/geoip@release/GeoLite2-ASN.mmdb'
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
                localDnsForwardTargetPort,
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
                cleanNftablesScript,
                nftablesScript,
                copyNftables,
                downloadNftables,
                systemdService,
                installScript,
                copyInstallScript
            } = tproxyModule;

            const addListener = () => {
                config.value.listeners.push({
                    name: `listener-${config.value.listeners.length + 1}`,
                    type: 'mixed',
                    port: getSuggestedListenerPort(config.value, uiState.value, 7895),
                    listen: '::',
                    udp: true,
                    cipher: '',
                    password: '',
                    network: ['tcp'],
                    target: '',
                    rule: '',
                    proxy: '',
                    token: '',
                    certificate: '',
                    'private-key': '',
                    'client-auth-type': '',
                    'client-auth-cert': '',
                    'ech-key': '',
                    'ech-cert': '',
                    users: [],
                    _usersText: '',
                    _shadowTlsText: '',
                    _kcpTunText: ''
                });
            };
            const removeListener = (idx) => {
                config.value.listeners.splice(idx, 1);
            };
            const sanitizeListenerUser = (user) => {
                if (!user || typeof user !== 'object') return { username: '', password: '' };
                return {
                    username: String(user.username || '').trim(),
                    password: String(user.password || '')
                };
            };
            const parseListenerUsersForEditor = (listener) => {
                if (!listener || typeof listener !== 'object') return [];
                if (Array.isArray(listener.users) && listener.users.length > 0) {
                    return listener.users.map(sanitizeListenerUser);
                }

                const rawText = String(listener._usersText || '').trim();
                if (!rawText) return [];

                try {
                    const parsedList = parseYamlSequenceText(rawText, (item) => item);
                    if (parsedList && parsedList.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
                        return parsedList.map(sanitizeListenerUser);
                    }
                } catch (err) {
                    // ignore parse failures here; validation will surface the exact error
                }

                try {
                    const parsedObject = parseYamlObjectText(rawText);
                    if (parsedObject && typeof parsedObject === 'object' && !Array.isArray(parsedObject)) {
                        return [sanitizeListenerUser(parsedObject)];
                    }
                } catch (err) {
                    // ignore parse failures here; validation will surface the exact error
                }

                return [];
            };
            const syncListenerUsersText = (listener) => {
                if (!listener || typeof listener !== 'object') return;
                const editorUsers = (Array.isArray(listener.users) ? listener.users : [])
                    .map(sanitizeListenerUser);
                const exportUsers = editorUsers.filter((user) => user.username || user.password);
                listener.users = editorUsers;
                listener._usersText = formatYamlSequenceText(exportUsers);
            };
            const ensureListenerUsers = (listener) => {
                if (!listener || typeof listener !== 'object') return;
                if (!Array.isArray(listener.users) || listener.users.length === 0) {
                    listener.users = parseListenerUsersForEditor(listener);
                } else {
                    listener.users = listener.users.map(sanitizeListenerUser);
                }
                syncListenerUsersText(listener);
            };
            const listenerUsesStructuredUsers = (listener) => ['mixed', 'http', 'socks'].includes(String(listener?.type || '').trim());
            const addListenerUser = (listener) => {
                if (!listener || typeof listener !== 'object') return;
                ensureListenerUsers(listener);
                listener.users.push({ username: '', password: '' });
                syncListenerUsersText(listener);
            };
            const removeListenerUser = (listener, userIndex) => {
                if (!listener || typeof listener !== 'object' || !Array.isArray(listener.users)) return;
                listener.users.splice(userIndex, 1);
                syncListenerUsersText(listener);
            };
            const tunnelListenerNetworkOptions = TUNNEL_LISTENER_NETWORK_OPTIONS.slice();
            const handleListenerTypeChange = (listener) => {
                if (!listener || typeof listener !== 'object') return;
                if (String(listener.type || '').trim() === 'tunnel') {
                    listener.network = normalizeTunnelListenerNetwork(listener.network);
                    if (!Array.isArray(listener.network) || listener.network.length === 0) {
                        listener.network = ['tcp'];
                    }
                    listener.target = String(listener.target || '').trim();
                    return;
                }

                if (listenerUsesStructuredUsers(listener)) {
                    ensureListenerUsers(listener);
                }

                if (!Array.isArray(listener.network)) {
                    listener.network = normalizeTunnelListenerNetwork(listener.network);
                }
            };
            onMounted(() => {
                if (!Array.isArray(config.value.listeners)) return;
                config.value.listeners.forEach((listener) => {
                    if (listenerUsesStructuredUsers(listener)) ensureListenerUsers(listener);
                });
            });
            const shadowsocksCipherOptions = getShadowsocksCipherOptions();
            const getListenerShadowsocksPasswordPlaceholder = (cipher) => {
                const normalizedCipher = String(cipher || '').trim();
                if (!normalizedCipher) return '请先选择加密算法';
                if (normalizedCipher === 'none') return 'none 模式无需密码';
                if (isShadowsocks2022Cipher(normalizedCipher)) return '点击右侧生成标准 Base64 密钥';
                return '请输入密码或点击右侧生成';
            };
            const generateListenerShadowsocksPassword = (listener) => {
                if (!listener || typeof listener !== 'object') return;
                const cipher = String(listener.cipher || '').trim();
                if (!cipher || !isSupportedShadowsocksCipher(cipher)) return;
                listener.password = generateShadowsocksPassword(cipher);
            };

            const proxiesModule = window.MihomoFeatureModules.createProxiesModule();
            const {
                parseSingleProxyNode,
                sanitizeProxyByCapabilities,
                sanitizeProxyNodeForYaml,
                getProxyNetworkOptions,
                proxySupportsTransport,
                proxySupportsToggle,
                proxyHasTlsSection,
                proxySupportsTlsClientFingerprint,
                getProxyValidationIssues,
                getProxyTlsMode
            } = proxiesModule;

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
                parseRuleString,
                RULE_TYPE_GROUPS,
                LOGIC_RULE_TYPE_GROUPS,
                IP_RULE_TYPES
            } = rulesModule;

            const providersModule = window.MihomoCore.createProvidersModule({
                ref,
                watch,
                config,
                uiState,
                providersList,
                ruleProvidersList,
                scrollToBottom,
                parseSingleProxyNode,
                sanitizeProxyNodeForYaml,
                sanitizeProxyByCapabilities,
                getProxyNetworkOptions,
                proxySupportsTransport,
                proxySupportsToggle,
                proxyHasTlsSection,
                proxySupportsTlsClientFingerprint,
                getProxyValidationIssues,
                getProxyTlsMode,
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
                groupIncludesAllProxies,
                groupIncludesAllProviders,
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
                addInlineChainProvider,
                addSourceChainProvider,
                getSubscriptionProviders,
                getInlineChainProviders,
                getProviderChainProviders,
                getChainProviders,
                getChainSourceProviders,
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
                getInlinePayloadPreview,
                getProviderFallbackSnapshotNames,
                getProviderFallbackDetachedNames,
                removeProviderFallbackPayloadNode,
                getProviderFallbackPayloadPreview
            } = providersModule;
            const proxyValidationIssues = computed(() => {
                return (config.value.proxies || []).map((proxy) => getProxyValidationIssues(proxy));
            });
            const validationModule = window.MihomoFeatureModules.createValidationModule({
                computed,
                config,
                uiState,
                providersList,
                ruleProvidersList,
                getProxyValidationIssues,
                getRuleProviderUrl
            });
            const {
                runtimeValidationIssues,
                runtimeValidationErrors,
                runtimeValidationWarnings
            } = validationModule;

            const yamlModule = window.MihomoFeatureModules.createYamlModule({
                ref,
                config,
                uiState,
                providersList,
                ruleProvidersList,
                sanitizeProxyNodeForYaml,
                getRuleProviderUrl,
                getDefaultConfig
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

            const importExportModule = window.MihomoCore.createImportExportModule({
                config,
                uiState,
                providersList,
                ruleProvidersList,
                fileInput,
                fullYaml,
                crashError,
                runtimeValidationErrors,
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
                normalizeListenAddress,
                deepMerge,
                clearPersistedStorage,
                setCacheWarning: (message) => {
                    cacheWarning.value = String(message || '');
                },
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
                addListenerUser,
                removeListenerUser,
                syncListenerUsersText,
                tunnelListenerNetworkOptions,
                handleListenerTypeChange,
                shadowsocksCipherOptions,
                isSupportedShadowsocksCipher,
                getListenerShadowsocksPasswordPlaceholder,
                generateListenerShadowsocksPassword,
                addProvider,
                addInlineChainProvider,
                addSourceChainProvider,
                getSubscriptionProviders,
                getInlineChainProviders,
                getProviderChainProviders,
                getChainProviders,
                getChainSourceProviders,
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
                groupIncludesAllProxies,
                groupIncludesAllProviders,
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
                getProviderFallbackSnapshotNames,
                getProviderFallbackDetachedNames,
                removeProviderFallbackPayloadNode,
                getProviderFallbackPayloadPreview,
                getProxyNetworkOptions,
                proxySupportsTransport,
                proxySupportsToggle,
                proxyHasTlsSection,
                proxySupportsTlsClientFingerprint,
                proxyValidationIssues,
                runtimeValidationIssues,
                runtimeValidationErrors,
                runtimeValidationWarnings,
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
                cleanNftablesScript,
                nftablesScript,
                copyNftables,
                downloadNftables,
                systemdService,
                installScript,
                copyInstallScript,
                updateRuleProviderName,
                resetGeoUrls,
                formatConditions,
                RULE_TYPE_GROUPS,
                LOGIC_RULE_TYPE_GROUPS,
                IP_RULE_TYPES,
                dnsListenPort,
                dnsListenPortInput,
                normalizeDnsListenInput,
                showHostsEditor,
                usingTransparentProxy,
                dnsHijackEnabled,
                dnsForwardConflict,
                dnsLocalForwardNeedsNon53,
                localDnsForwardTargetPort,
                dnsPathPreview,
                specifiedPortsContain53,
                cacheWarning,
                dismissCacheWarning,
                availableSubRuleNames,
                hasNameserverPolicyText,
                hasDirectNameserverEntries,
                canUseDirectNameserverFollowPolicy,
                crashError,
                askConfirm
            };
        }
    }).mount('#app');
    };

})(window);
