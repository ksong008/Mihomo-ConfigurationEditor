(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};

    const cloneJsonValue = (value, fallback = null) => {
        try {
            return JSON.parse(JSON.stringify(value));
        } catch (err) {
            return fallback;
        }
    };

    const createProviderState = (overrides = {}) => ({
        name: '',
        type: 'http',
        url: '',
        path: '',
        interval: 3600,
        proxy: '',
        sizeLimit: '',
        ageSecretKey: '',
        headers: '',
        filter: '',
        excludeFilter: '',
        excludeType: '',
        healthCheckEnable: true,
        healthUrl: 'https://www.gstatic.com/generate_204',
        healthCheckInterval: 600,
        overrideDialerProxy: '',
        overrideAdditionalPrefix: '',
        overrideAdditionalSuffix: '',
        overrideProxyName: '',
        overrideUdp: '',
        overrideUdpOverTcp: '',
        overrideTfo: '',
        overrideMptcp: '',
        overrideSkipCertVerify: '',
        overrideUp: '',
        overrideDown: '',
        overrideInterfaceName: '',
        overrideRoutingMark: '',
        overrideIpVersion: '',
        inlineProxies: [],
        _fallbackPayloadProxyNames: [],
        _fallbackPayload: [],
        _unsupportedOverrideKeys: [],
        _unsupportedOverride: {},
        lazy: true,
        healthCheckLazy: true,
        healthCheckTimeout: 5000,
        healthExpectedStatus: '',
        ...overrides
    });

    const createRuleProviderState = (overrides = {}) => ({
        name: '',
        type: 'http',
        file: '',
        behavior: 'domain',
        format: 'mrs',
        interval: 86400,
        autoUrl: true,
        customUrl: '',
        path: '',
        pathInBundle: '',
        proxy: '',
        sizeLimit: '',
        headers: '',
        payload: '',
        _collapsed: false,
        ...overrides
    });

    const getRuleProviderUrl = (rp, options = {}) => {
        if (!rp || !rp.autoUrl) return rp ? rp.customUrl : '';
        const targetName = rp.file ? String(rp.file).trim() : '';
        if (!targetName) return '';
        const base = options.useMirrorForRuleProviders
            ? 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo'
            : 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo';
        const folder = rp.behavior === 'ipcidr' ? 'geoip' : 'geosite';
        const ext = rp.format === 'text' ? 'list' : rp.format;
        return `${base}/${folder}/${targetName}.${ext}`;
    };

    window.MihomoCore.ProviderModel = Object.freeze({
        cloneJsonValue,
        createProviderState,
        createRuleProviderState,
        getRuleProviderUrl
    });
})(window);
