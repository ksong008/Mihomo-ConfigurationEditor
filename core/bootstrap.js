(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 mihomo.helpers.js');
    }

    const { createApp, ref, computed, watch, onMounted, nextTick, onErrorCaptured } = Vue;
    const {
        getListenPort,
        normalizeNftablesConfig,
        getSanitizedUiStateForSave,
        parseYamlObjectText,
        formatYamlMapText,
        deepMerge
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
        !window.MihomoFeatureModules.createDnsModule ||
        !window.MihomoFeatureModules.createTproxyModule ||
        !window.MihomoFeatureModules.createRulesModule ||
        !window.MihomoFeatureModules.createYamlModule
    ) {
        throw new Error('功能模块未加载，请确认先引入 ./core/state.js ./core/ui-runtime.js ./core/providers.js ./core/import-export.js ./core/persistence.js ./modules/proxies.js ./modules/dns.js ./modules/tproxy.js ./modules/rules.js ./modules/yaml.js');
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

            const addListener = () => {
                config.value.listeners.push({
                    name: `listener-${config.value.listeners.length + 1}`,
                    type: 'mixed',
                    port: 7890,
                    listen: '::',
                    udp: true,
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
                    _usersText: ''
                });
            };
            const removeListener = (idx) => {
                config.value.listeners.splice(idx, 1);
            };

            const proxiesModule = window.MihomoFeatureModules.createProxiesModule();
            const {
                parseSingleProxyNode,
                sanitizeProxyByCapabilities,
                sanitizeProxyNodeForYaml,
                getProxyNetworkOptions: proxyModuleGetNetworkOptions,
                proxySupportsTransport: proxyModuleSupportsTransport,
                proxySupportsToggle: proxyModuleSupportsToggle,
                proxyShowsTlsSection: proxyModuleShowsTlsSection,
                proxyShowsSmuxSection: proxyModuleShowsSmuxSection
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
                getProxyNetworkOptions: proxyModuleGetNetworkOptions,
                proxySupportsTransport: proxyModuleSupportsTransport,
                proxySupportsToggle: proxyModuleSupportsToggle,
                proxyShowsTlsSection: proxyModuleShowsTlsSection,
                proxyShowsSmuxSection: proxyModuleShowsSmuxSection,
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
                getProxyNetworkOptions,
                proxySupportsTransport,
                proxySupportsToggle,
                proxyShowsTlsSection,
                proxyShowsSmuxSection
            } = providersModule;

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
                getProxyNetworkOptions,
                proxySupportsTransport,
                proxySupportsToggle,
                proxyShowsTlsSection,
                proxyShowsSmuxSection,
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
                IP_RULE_TYPES,
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
