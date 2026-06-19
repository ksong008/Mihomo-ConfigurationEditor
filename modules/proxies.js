(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createProxiesModule = function () {
        const parseYamlMapText = window.MihomoHelpers && typeof window.MihomoHelpers.parseYamlMapText === 'function'
            ? window.MihomoHelpers.parseYamlMapText
            : () => undefined;
        const parseYamlObjectText = window.MihomoHelpers && typeof window.MihomoHelpers.parseYamlObjectText === 'function'
            ? window.MihomoHelpers.parseYamlObjectText
            : () => undefined;
        const formatYamlMapText = window.MihomoHelpers && typeof window.MihomoHelpers.formatYamlMapText === 'function'
            ? window.MihomoHelpers.formatYamlMapText
            : (value) => {
                try {
                    return JSON.stringify(value || {}, null, 2);
                } catch (err) {
                    return '';
                }
            };
        const formatYamlObjectText = window.MihomoHelpers && typeof window.MihomoHelpers.formatYamlObjectText === 'function'
            ? window.MihomoHelpers.formatYamlObjectText
            : (value) => {
                try {
                    return JSON.stringify(value || {}, null, 2);
                } catch (err) {
                    return '';
                }
            };
        const proxySchema = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxySchema;
        if (!proxySchema) {
            throw new Error('ProxySchema 未加载，请确认先引入 ./modules/proxy-schema.js');
        }
        const proxyNodeModel = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxyNodeModel;
        if (!proxyNodeModel) {
            throw new Error('ProxyNodeModel 未加载，请确认先引入 ./modules/proxy-node-model.js');
        }
        const proxyNodeValidation = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxyNodeValidation;
        if (!proxyNodeValidation) {
            throw new Error('ProxyNodeValidation 未加载，请确认先引入 ./modules/proxy-node-validation.js');
        }
        const proxyNodeYaml = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxyNodeYaml;
        if (!proxyNodeYaml) {
            throw new Error('ProxyNodeYaml 未加载，请确认先引入 ./modules/proxy-node-yaml.js');
        }
        const {
            getProxyNetworkOptions,
            proxySupportsTransport,
            getProxyTlsMode,
            proxySupportsToggle,
            proxySupportsTlsClientFingerprint,
            proxyHasTlsSection,
            resolveProxyCapabilities,
            sanitizeProxyByCapabilities
        } = proxySchema;
        const { parseSingleProxyNode } = proxyNodeModel.createProxyNodeModel({
            formatYamlMapText,
            formatYamlObjectText
        });
        const { getProxyValidationIssues } = proxyNodeValidation.createProxyNodeValidation({
            parseSingleProxyNode,
            parseYamlObjectText
        });
        const { sanitizeProxyNodeForYaml } = proxyNodeYaml.createProxyNodeYaml({
            parseSingleProxyNode,
            parseYamlMapText,
            parseYamlObjectText
        });
        return {
            parseSingleProxyNode,
            sanitizeProxyNodeForYaml,
            getProxyNetworkOptions,
            proxySupportsTransport,
            proxySupportsToggle,
            resolveProxyCapabilities,
            sanitizeProxyByCapabilities,
            proxyHasTlsSection,
            proxySupportsTlsClientFingerprint,
            getProxyValidationIssues,
            getProxyTlsMode
        };
    };
})(window);
