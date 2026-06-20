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
        !window.MihomoCore.ProviderModel ||
        !window.MihomoCore.ProviderGroupModel ||
        !window.MihomoCore.ProviderFallbackModel ||
        !window.MihomoCore.ProviderRenameModel ||
        !window.MihomoCore.createProviderGroupEditor ||
        !window.MihomoCore.createProviderSubscriptionEditor ||
        !window.MihomoCore.createRuleProviderEditor ||
        !window.MihomoCore.createProvidersModule ||
        !window.MihomoCore.ImportModel ||
        !window.MihomoCore.createImportExportModule ||
        !window.MihomoCore.createPersistenceModule ||
        !window.MihomoCore.createBootstrapUiModule ||
        !window.MihomoCore.createListenerEditor ||
        !window.MihomoFeatureModules ||
        !window.MihomoFeatureModules.ProxyNodeUtils ||
        !window.MihomoFeatureModules.ProxyNodeModel ||
        !window.MihomoFeatureModules.ProxyNodeValidation ||
        !window.MihomoFeatureModules.ProxyNodeYaml ||
        !window.MihomoFeatureModules.createProxiesModule ||
        !window.MihomoFeatureModules.ValidationHelpers ||
        !window.MihomoFeatureModules.ValidationDns ||
        !window.MihomoFeatureModules.createValidationModule ||
        !window.MihomoFeatureModules.createDnsModule ||
        !window.MihomoFeatureModules.TproxyBuilders ||
        !window.MihomoFeatureModules.createTproxyModule ||
        !window.MihomoFeatureModules.RuleParser ||
        !window.MihomoFeatureModules.createRulesModule ||
        !window.MihomoFeatureModules.YamlBuilders ||
        !window.MihomoFeatureModules.createYamlModule
    ) {
        throw new Error('功能模块未加载，请确认先引入 ./core/state.js ./core/ui-runtime.js ./core/provider-model.js ./core/provider-group-model.js ./core/provider-fallback-model.js ./core/provider-rename-model.js ./core/provider-group-editor.js ./core/provider-subscription-editor.js ./core/rule-provider-editor.js ./core/providers.js ./core/import-model.js ./core/import-export.js ./core/persistence.js ./core/bootstrap-ui.js ./core/listener-editor.js ./modules/proxy-schema.js ./modules/proxy-node-utils.js ./modules/proxy-node-model.js ./modules/proxy-node-validation.js ./modules/proxy-node-yaml.js ./modules/proxies.js ./modules/validation-helpers.js ./modules/validation-dns.js ./modules/validation-listeners.js ./modules/validation-providers.js ./modules/validation-groups-rules.js ./modules/validation.js ./modules/dns.js ./modules/tproxy-builders.js ./modules/tproxy.js ./modules/rule-parser.js ./modules/rules.js ./modules/yaml-builders.js ./modules/yaml.js');
    }

    const STORAGE_VERSION = 20;
    const STORAGE_KEY_PREFIX = 'mihomo_web_config';
    const STORAGE_KEY = `${STORAGE_KEY_PREFIX}_v${STORAGE_VERSION}`;
    const STORAGE_BACKUP_KEY = `${STORAGE_KEY}_backup`;
    const RESTORE_LEGACY_STORAGE_KEYS = ['mihomo_web_config_v19', 'mihomo_web_config_v19_backup', 'mihomo_web_config_v18', 'mihomo_web_config_v18_backup', 'mihomo_web_config_v17'];
    const CLEANUP_STORAGE_KEYS = ['mihomo_web_config_v17', 'mihomo_web_config_v18', 'mihomo_web_config_v18_backup', 'mihomo_web_config_v19', 'mihomo_web_config_v19_backup'];

    createApp({
        setup() {
            const bootstrapUiModule = window.MihomoCore.createBootstrapUiModule({
                ref,
                onMounted,
                nextTick,
                onErrorCaptured,
                storageKey: STORAGE_KEY,
                storageBackupKey: STORAGE_BACKUP_KEY,
                cleanupStorageKeys: CLEANUP_STORAGE_KEYS
            });
            const {
                crashError,
                cacheWarning,
                clearPersistedStorage,
                forceClearCache,
                dismissCacheWarning
            } = bootstrapUiModule;

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
            const listenerEditorModule = window.MihomoCore.createListenerEditor({
                onMounted,
                config,
                uiState,
                parseYamlObjectText,
                parseYamlSequenceText,
                formatYamlSequenceText,
                getSuggestedListenerPort,
                normalizeTunnelListenerNetwork,
                tunnelListenerNetworkOptions: TUNNEL_LISTENER_NETWORK_OPTIONS,
                getShadowsocksCipherOptions,
                isSupportedShadowsocksCipher,
                isShadowsocks2022Cipher,
                generateShadowsocksPassword
            });
            const {
                addListener,
                removeListener,
                addListenerUser,
                removeListenerUser,
                syncListenerUsersText,
                tunnelListenerNetworkOptions,
                handleListenerTypeChange,
                shadowsocksCipherOptions,
                getListenerShadowsocksPasswordPlaceholder,
                generateListenerShadowsocksPassword
            } = listenerEditorModule;

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
                getAvailableEmptyFallbackMembers,
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
                getAvailableEmptyFallbackMembers,
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
