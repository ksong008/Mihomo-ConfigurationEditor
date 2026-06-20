(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createProvidersModule = function (ctx) {
        const {
            config,
            watch,
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
        } = ctx;
        if (!window.MihomoCore.createProviderGroupEditor) {
            throw new Error('ProviderGroupEditor 未加载，请确认先引入 ./core/provider-group-editor.js');
        }
        if (!window.MihomoCore.createProviderSubscriptionEditor) {
            throw new Error('ProviderSubscriptionEditor 未加载，请确认先引入 ./core/provider-subscription-editor.js');
        }
        if (!window.MihomoCore.createRuleProviderEditor) {
            throw new Error('RuleProviderEditor 未加载，请确认先引入 ./core/rule-provider-editor.js');
        }

        const groupEditor = window.MihomoCore.createProviderGroupEditor(ctx);
        const subscriptionEditor = window.MihomoCore.createProviderSubscriptionEditor(ctx);
        const ruleProviderEditor = window.MihomoCore.createRuleProviderEditor(ctx);

        const normalizeProxyTransportState = () => {
            (config.value.proxies || []).forEach((px) => {
                if (!px || typeof px !== 'object') return;
                if (typeof sanitizeProxyByCapabilities === 'function') {
                    sanitizeProxyByCapabilities(px);
                    return;
                }
                const options = getProxyNetworkOptions(px.type);
                const allowed = new Set(options.map((item) => item.value));
                if (allowed.size === 0) {
                    px.network = 'tcp';
                } else if (!allowed.has(px.network)) {
                    px.network = options[0].value;
                }
                const tlsMode = getProxyTlsMode(px.type);
                if (tlsMode === 'required') {
                    px.tls = true;
                } else if (!proxySupportsToggle(px.type, 'tls')) {
                    px.tls = false;
                }
                if (!proxySupportsToggle(px.type, 'reality')) {
                    px.reality = false;
                }
                if (!proxySupportsToggle(px.type, 'smux') || (proxySupportsTransport(px.type) && px.network !== 'tcp')) {
                    if (px.smux && typeof px.smux === 'object') {
                        px.smux.enabled = false;
                    }
                }
                if (px.type !== 'trojan' && px['ss-opts']) {
                    px['ss-opts'].enabled = false;
                }
                if (tlsMode === 'none' && !proxySupportsToggle(px.type, 'reality')) {
                    px.reality = false;
                    px.tls = false;
                }
            });
        };

        const addManualProxy = () => {
            config.value.proxies.push(parseSingleProxyNode({ type: 'vless' }));
            ctx.scrollToBottom();
        };

        watch(
            () => config.value.proxies,
            () => {
                normalizeProxyTransportState();
                subscriptionEditor.normalizeProviderFallbackPayloadState();
            },
            { immediate: true, deep: true, flush: 'sync' }
        );

        const clearLists = () => {
            if (askConfirm('确定要清空所有的节点、订阅和规则列表吗？')) {
                config.value.proxies = [];
                config.value['proxy-groups'] = [];
                ctx.providersList.value = [];
                ctx.ruleProvidersList.value = [];
                ctx.uiState.value.rules = [];
            }
        };

        return {
            addManualProxy,
            clearLists,
            ...groupEditor,
            ...subscriptionEditor,
            ...ruleProviderEditor,
            sanitizeProxyNodeForYaml,
            getProxyNetworkOptions,
            proxySupportsTransport,
            proxySupportsToggle,
            proxyHasTlsSection,
            proxySupportsTlsClientFingerprint,
            getProxyValidationIssues
        };
    };
})(window);
