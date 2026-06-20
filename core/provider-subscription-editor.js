(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createProviderSubscriptionEditor = function (ctx) {
        const {
            watch,
            config,
            uiState,
            providersList,
            ruleProvidersList,
            sanitizeProxyNodeForYaml
        } = ctx;
        const providerModel = window.MihomoCore && window.MihomoCore.ProviderModel;
        if (!providerModel) {
            throw new Error('ProviderModel 未加载，请确认先引入 ./core/provider-model.js');
        }
        const providerFallbackModel = window.MihomoCore && window.MihomoCore.ProviderFallbackModel;
        if (!providerFallbackModel) {
            throw new Error('ProviderFallbackModel 未加载，请确认先引入 ./core/provider-fallback-model.js');
        }
        const providerRenameModel = window.MihomoCore && window.MihomoCore.ProviderRenameModel;
        if (!providerRenameModel) {
            throw new Error('ProviderRenameModel 未加载，请确认先引入 ./core/provider-rename-model.js');
        }
        const {
            cloneJsonValue,
            createProviderState
        } = providerModel;
        const {
            normalizeProviderFallbackPayloadState: normalizeProviderFallbackPayload,
            getInlinePayloadPreview: buildInlinePayloadPreview,
            getProviderFallbackSnapshotNames,
            getProviderFallbackDetachedNames: buildProviderFallbackDetachedNames,
            removeProviderFallbackPayloadNode,
            getProviderFallbackPayloadPreview: buildProviderFallbackPayloadPreview
        } = providerFallbackModel;
        const { createProviderRenameTracker } = providerRenameModel;
        const renameTracker = createProviderRenameTracker();

        const scrollProviderCardIntoView = (selector) => {
            window.requestAnimationFrame(() => {
                window.requestAnimationFrame(() => {
                    const scrollBox = document.getElementById('main-scroll');
                    const target = document.querySelector(selector);
                    if (!scrollBox || !target) return;

                    const stickyHeader = target.closest('.bg-white.p-5.rounded-xl')?.querySelector('.sticky.top-0');
                    const headerOffset = stickyHeader ? stickyHeader.getBoundingClientRect().height : 72;
                    const containerRect = scrollBox.getBoundingClientRect();
                    const targetRect = target.getBoundingClientRect();
                    const absoluteTop = targetRect.top - containerRect.top + scrollBox.scrollTop;
                    const safeTop = Math.max(0, absoluteTop - headerOffset - 12);

                    scrollBox.scrollTo({ top: safeTop, behavior: 'smooth' });
                });
            });
        };

        const normalizeChainProvidersState = () => {
            const sourceProviders = (providersList.value || []).filter((p) => p && !p._chainMode);
            (providersList.value || []).forEach((p) => {
                if (!p || p._chainMode !== 'provider') return;
                const source = sourceProviders.find((item) => item.name === p._sourceProviderName && ['http', 'file'].includes(item.type));
                if (!source) return;
                p.type = source.type;
                p.url = source.url;
                p.path = source.path;
                p.interval = source.interval;
                p.proxy = source.proxy;
                p.sizeLimit = source.sizeLimit;
                p.ageSecretKey = source.ageSecretKey;
                p.headers = source.headers;
                p.lazy = source.lazy;
                p.healthCheckEnable = source.healthCheckEnable;
                p.healthUrl = source.healthUrl;
                p.healthCheckInterval = source.healthCheckInterval;
                p.healthCheckLazy = source.healthCheckLazy;
                p.healthCheckTimeout = source.healthCheckTimeout;
                p.healthExpectedStatus = source.healthExpectedStatus;
            });
        };

        const normalizeProviderFallbackPayloadState = () => {
            normalizeProviderFallbackPayload({
                providers: providersList.value,
                proxies: config.value.proxies,
                cloneJsonValue,
                sanitizeProxyNodeForYaml
            });
        };

        watch(
            () => providersList.value,
            () => {
                normalizeChainProvidersState();
                normalizeProviderFallbackPayloadState();
            },
            { immediate: true, deep: true, flush: 'sync' }
        );

        const ensureRenameSnapshots = () => {
            renameTracker.ensureSnapshots({
                providers: providersList.value,
                proxies: config.value.proxies,
                groups: config.value['proxy-groups']
            });
        };

        watch(
            [
                () => providersList.value,
                () => config.value.proxies,
                () => config.value['proxy-groups'],
                () => (providersList.value || []).length,
                () => (config.value.proxies || []).length,
                () => (config.value['proxy-groups'] || []).length
            ],
            () => {
                ensureRenameSnapshots();
            },
            { immediate: true, flush: 'sync' }
        );

        const pickPanel = (p) => {
            uiState.value.selectedPanel = p.id;
            config.value['external-ui-url'] = uiState.value.useMirrorForPanels ? p.mirrorUrl : p.rawUrl;
        };

        const addProvider = () => {
            const nextName = `Provider-${(providersList.value || []).length + 1}`;
            providersList.value.push(createProviderState({ name: nextName }));
            scrollProviderCardIntoView(`[data-provider-kind="subscription"][data-provider-name="${CSS.escape(nextName)}"]`);
        };

        const addInlineChainProvider = () => {
            const nextName = `Chain-${(providersList.value || []).length + 1}`;
            providersList.value.push(createProviderState({
                name: nextName,
                type: 'inline',
                _chainMode: 'inline',
                _sourceProviderName: ''
            }));
            window.requestAnimationFrame(() => {
                const detail = document.getElementById('inline-chain-details');
                if (detail && detail.tagName === 'DETAILS') detail.open = true;
                scrollProviderCardIntoView(`[data-provider-kind="inline-chain"][data-provider-name="${CSS.escape(nextName)}"]`);
            });
        };

        const addSourceChainProvider = () => {
            const nextName = `Provider-Chain-${(providersList.value || []).length + 1}`;
            providersList.value.push(createProviderState({
                name: nextName,
                type: 'http',
                _chainMode: 'provider',
                _sourceProviderName: ''
            }));
            window.requestAnimationFrame(() => {
                const detail = document.getElementById('inline-chain-details');
                if (detail && detail.tagName === 'DETAILS') detail.open = true;
                scrollProviderCardIntoView(`[data-provider-kind="inline-chain"][data-provider-name="${CSS.escape(nextName)}"]`);
            });
        };

        const getSubscriptionProviders = () => (providersList.value || []).filter((p) => p && !p._chainMode);
        const getInlineChainProviders = () => (providersList.value || []).filter((p) => p && p._chainMode === 'inline');
        const getProviderChainProviders = () => (providersList.value || []).filter((p) => p && p._chainMode === 'provider');
        const getChainProviders = () => (providersList.value || []).filter((p) => p && p._chainMode);
        const getChainSourceProviders = () => getSubscriptionProviders().filter((p) => ['http', 'file'].includes(p.type));

        const removeProvider = (idx) => providersList.value.splice(idx, 1);

        const updateProviderName = (p, newName) => {
            renameTracker.updateProviderName({
                provider: p,
                newName,
                providers: providersList.value,
                groups: config.value['proxy-groups']
            });
        };

        const updateProxyName = (px, newName) => {
            renameTracker.updateProxyName({
                proxy: px,
                newName,
                providers: providersList.value,
                ruleProviders: ruleProvidersList.value,
                proxies: config.value.proxies,
                groups: config.value['proxy-groups'],
                rules: uiState.value.rules
            });
        };

        const updateGroupName = (g, newName) => {
            renameTracker.updateGroupName({
                group: g,
                newName,
                providers: providersList.value,
                ruleProviders: ruleProvidersList.value,
                proxies: config.value.proxies,
                groups: config.value['proxy-groups'],
                rules: uiState.value.rules
            });
        };

        const getInlinePayloadPreview = (inlineProxies) => {
            return buildInlinePayloadPreview({
                inlineProxies,
                proxies: config.value.proxies,
                sanitizeProxyNodeForYaml,
                dumpYaml: jsyaml.dump
            });
        };

        const getProviderFallbackDetachedNames = (provider) => {
            return buildProviderFallbackDetachedNames({
                provider,
                proxies: config.value.proxies
            });
        };

        const getProviderFallbackPayloadPreview = (provider) => {
            return buildProviderFallbackPayloadPreview({
                provider,
                proxies: config.value.proxies,
                cloneJsonValue,
                sanitizeProxyNodeForYaml,
                dumpYaml: jsyaml.dump
            });
        };

        return {
            pickPanel,
            normalizeProviderFallbackPayloadState,
            addProvider,
            addInlineChainProvider,
            addSourceChainProvider,
            getSubscriptionProviders,
            getInlineChainProviders,
            getProviderChainProviders,
            getChainProviders,
            getChainSourceProviders,
            removeProvider,
            updateProviderName,
            updateProxyName,
            updateGroupName,
            getInlinePayloadPreview,
            getProviderFallbackSnapshotNames,
            getProviderFallbackDetachedNames,
            removeProviderFallbackPayloadNode,
            getProviderFallbackPayloadPreview
        };
    };
})(window);
