(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};

    const normalizeName = (value) => String(value || '').trim();

    const sameStringList = (left, right) => {
        if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
        return left.every((item, index) => item === right[index]);
    };

    const serialize = (value) => {
        try {
            return JSON.stringify(value);
        } catch (err) {
            return '';
        }
    };

    const cloneWith = (cloneJsonValue, value) => {
        if (typeof cloneJsonValue === 'function') return cloneJsonValue(value, value);
        try {
            return JSON.parse(JSON.stringify(value));
        } catch (err) {
            return value;
        }
    };

    const buildProxyMap = (proxies = []) => {
        const proxyMap = new Map();
        (Array.isArray(proxies) ? proxies : []).forEach((px) => {
            const name = normalizeName(px && px.name);
            if (!name || proxyMap.has(name)) return;
            proxyMap.set(name, px);
        });
        return proxyMap;
    };

    const getFallbackSelectedNames = (provider) => Array.from(new Set(
        (Array.isArray(provider && provider._fallbackPayloadProxyNames) ? provider._fallbackPayloadProxyNames : [])
            .map(normalizeName)
            .filter(Boolean)
    ));

    const buildFallbackSnapshotMap = (provider, cloneJsonValue) => {
        const snapshotMap = new Map();
        (Array.isArray(provider && provider._fallbackPayload) ? provider._fallbackPayload : []).forEach((item) => {
            if (!item || typeof item !== 'object') return;
            const name = normalizeName(item.name);
            if (!name || snapshotMap.has(name)) return;
            snapshotMap.set(name, cloneWith(cloneJsonValue, item));
        });
        return snapshotMap;
    };

    const buildFallbackPayloadNodes = (options = {}) => {
        const provider = options.provider;
        const proxyMap = options.proxyMap || buildProxyMap(options.proxies);
        const snapshotMap = options.snapshotMap || buildFallbackSnapshotMap(provider, options.cloneJsonValue);
        const sanitizeProxyNodeForYaml = options.sanitizeProxyNodeForYaml;

        return getFallbackSelectedNames(provider)
            .map((name) => {
                const liveProxy = proxyMap.get(name);
                if (liveProxy && typeof sanitizeProxyNodeForYaml === 'function') {
                    return sanitizeProxyNodeForYaml(liveProxy);
                }
                return snapshotMap.get(name) || null;
            })
            .filter(Boolean);
    };

    const normalizeProviderFallbackPayloadState = (options = {}) => {
        const providers = Array.isArray(options.providers) ? options.providers : [];
        const proxyMap = buildProxyMap(options.proxies);

        providers.forEach((provider) => {
            if (!provider || provider._chainMode || !['http', 'file'].includes(provider.type)) return;

            const selectedNames = getFallbackSelectedNames(provider);
            const snapshotMap = buildFallbackSnapshotMap(provider, options.cloneJsonValue);
            const nextPayload = buildFallbackPayloadNodes({
                provider,
                proxyMap,
                snapshotMap,
                sanitizeProxyNodeForYaml: options.sanitizeProxyNodeForYaml
            });

            if (!sameStringList(provider._fallbackPayloadProxyNames, selectedNames)) {
                provider._fallbackPayloadProxyNames = selectedNames;
            }
            if (serialize(provider._fallbackPayload) !== serialize(nextPayload)) {
                provider._fallbackPayload = nextPayload;
            }
        });
    };

    const dumpPayloadPreview = (nodes, dumpYaml) => {
        try {
            return dumpYaml(nodes, { indent: 2, lineWidth: -1, sortKeys: false });
        } catch (err) {
            return '# Preview Error';
        }
    };

    const getInlinePayloadPreview = (options = {}) => {
        const inlineProxies = options.inlineProxies;
        if (!inlineProxies || inlineProxies.length === 0) return '[]';

        const proxyMap = buildProxyMap(options.proxies);
        const sanitizeProxyNodeForYaml = options.sanitizeProxyNodeForYaml;
        const nodes = inlineProxies.map((name) => {
            const px = proxyMap.get(normalizeName(name));
            if (!px || typeof sanitizeProxyNodeForYaml !== 'function') return null;
            return sanitizeProxyNodeForYaml(px);
        }).filter(Boolean);

        return dumpPayloadPreview(nodes, options.dumpYaml);
    };

    const getProviderFallbackSnapshotNames = (provider) => {
        if (!provider || !Array.isArray(provider._fallbackPayload)) return [];
        return provider._fallbackPayload
            .map((item) => normalizeName(item && item.name))
            .filter(Boolean);
    };

    const getProviderFallbackDetachedNames = (options = {}) => {
        const liveNames = new Set(
            (Array.isArray(options.proxies) ? options.proxies : [])
                .map((item) => normalizeName(item && item.name))
                .filter(Boolean)
        );
        return getProviderFallbackSnapshotNames(options.provider).filter((name) => !liveNames.has(name));
    };

    const removeProviderFallbackPayloadNode = (provider, name) => {
        if (!provider || typeof provider !== 'object') return;
        const target = normalizeName(name);
        if (!target) return;
        if (Array.isArray(provider._fallbackPayloadProxyNames)) {
            provider._fallbackPayloadProxyNames = provider._fallbackPayloadProxyNames
                .map(normalizeName)
                .filter((item) => item && item !== target);
        }
        if (Array.isArray(provider._fallbackPayload)) {
            provider._fallbackPayload = provider._fallbackPayload.filter((item) => normalizeName(item && item.name) !== target);
        }
    };

    const getProviderFallbackPayloadPreview = (options = {}) => {
        if (!options.provider) return '[]';
        const nodes = buildFallbackPayloadNodes({
            provider: options.provider,
            proxies: options.proxies,
            sanitizeProxyNodeForYaml: options.sanitizeProxyNodeForYaml,
            cloneJsonValue: options.cloneJsonValue
        });
        return dumpPayloadPreview(nodes, options.dumpYaml);
    };

    window.MihomoCore.ProviderFallbackModel = Object.freeze({
        buildProxyMap,
        getFallbackSelectedNames,
        buildFallbackSnapshotMap,
        buildFallbackPayloadNodes,
        normalizeProviderFallbackPayloadState,
        getInlinePayloadPreview,
        getProviderFallbackSnapshotNames,
        getProviderFallbackDetachedNames,
        removeProviderFallbackPayloadNode,
        getProviderFallbackPayloadPreview
    });
})(window);
