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

            const proxiesModule = window.MihomoFeatureModules.createProxiesModule();
            const { parseSingleProxyNode } = proxiesModule;

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
    };

})(window);
