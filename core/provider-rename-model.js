(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};

    const replaceNameInList = (list, oldName, newName) => {
        if (!Array.isArray(list) || oldName === newName) return;
        for (let i = 0; i < list.length; i++) {
            if (list[i] === oldName) list[i] = newName;
        }
    };

    const replaceDialerProxyName = (target, oldName, newName, key = 'dialer-proxy') => {
        if (!target || typeof target !== 'object' || oldName === newName) return;
        if (target[key] === oldName) target[key] = newName;
    };

    const replaceProviderDialerRefs = (providers, oldName, newName) => {
        (Array.isArray(providers) ? providers : []).forEach((p) => {
            if (!p || typeof p !== 'object') return;
            if (p.proxy === oldName) p.proxy = newName;
            if (p.overrideDialerProxy === oldName) p.overrideDialerProxy = newName;
        });
    };

    const replaceRuleProviderProxyRefs = (ruleProviders, oldName, newName) => {
        (Array.isArray(ruleProviders) ? ruleProviders : []).forEach((rp) => {
            if (!rp || typeof rp !== 'object') return;
            if (rp.proxy === oldName) rp.proxy = newName;
        });
    };

    const replaceProviderInlineProxyRefs = (providers, oldName, newName) => {
        (Array.isArray(providers) ? providers : []).forEach((p) => {
            if (!p || typeof p !== 'object') return;
            replaceNameInList(p.inlineProxies, oldName, newName);
            replaceNameInList(p._fallbackPayloadProxyNames, oldName, newName);
            if (Array.isArray(p._fallbackPayload)) {
                p._fallbackPayload.forEach((item) => {
                    if (item && typeof item === 'object' && item.name === oldName) {
                        item.name = newName;
                    }
                });
            }
        });
    };

    const replaceProviderSourceRefs = (providers, oldName, newName) => {
        (Array.isArray(providers) ? providers : []).forEach((p) => {
            if (!p || typeof p !== 'object') return;
            if (p._sourceProviderName === oldName) p._sourceProviderName = newName;
        });
    };

    const replaceRuleTargets = (rules, oldName, newName) => {
        (Array.isArray(rules) ? rules : []).forEach((r) => {
            if (r && r.target === oldName) r.target = newName;
        });
    };

    const createProviderRenameTracker = () => {
        const providerNameSnapshots = new WeakMap();
        const proxyNameSnapshots = new WeakMap();
        const groupNameSnapshots = new WeakMap();

        const ensureSnapshots = (options = {}) => {
            (Array.isArray(options.providers) ? options.providers : []).forEach((p) => {
                if (p && typeof p === 'object' && !providerNameSnapshots.has(p)) {
                    providerNameSnapshots.set(p, String(p.name || ''));
                }
            });

            (Array.isArray(options.proxies) ? options.proxies : []).forEach((px) => {
                if (px && typeof px === 'object' && !proxyNameSnapshots.has(px)) {
                    proxyNameSnapshots.set(px, String(px.name || ''));
                }
            });

            (Array.isArray(options.groups) ? options.groups : []).forEach((g) => {
                if (g && typeof g === 'object' && !groupNameSnapshots.has(g)) {
                    groupNameSnapshots.set(g, String(g.name || ''));
                }
            });
        };

        const updateProviderName = (options = {}) => {
            const provider = options.provider;
            if (!provider || typeof provider !== 'object') return;
            const oldName = providerNameSnapshots.has(provider) ? providerNameSnapshots.get(provider) : String(provider.name || '');
            const newName = options.newName;
            provider.name = newName;

            if (oldName === newName) return;

            (Array.isArray(options.groups) ? options.groups : []).forEach((g) => {
                replaceNameInList(g && g.use, oldName, newName);
            });
            replaceProviderSourceRefs(options.providers, oldName, newName);

            providerNameSnapshots.set(provider, String(newName || ''));
        };

        const updateProxyName = (options = {}) => {
            const proxy = options.proxy;
            if (!proxy || typeof proxy !== 'object') return;
            const oldName = proxyNameSnapshots.has(proxy) ? proxyNameSnapshots.get(proxy) : String(proxy.name || '');
            const newName = options.newName;
            proxy.name = newName;

            if (oldName === newName) return;

            (Array.isArray(options.groups) ? options.groups : []).forEach((g) => {
                replaceNameInList(g && g.proxies, oldName, newName);
            });

            replaceProviderDialerRefs(options.providers, oldName, newName);
            replaceRuleProviderProxyRefs(options.ruleProviders, oldName, newName);
            replaceProviderInlineProxyRefs(options.providers, oldName, newName);

            (Array.isArray(options.proxies) ? options.proxies : []).forEach((item) => {
                if (item !== proxy) replaceDialerProxyName(item, oldName, newName);
            });

            replaceRuleTargets(options.rules, oldName, newName);
            proxyNameSnapshots.set(proxy, String(newName || ''));
        };

        const updateGroupName = (options = {}) => {
            const group = options.group;
            if (!group || typeof group !== 'object') return;
            const oldName = groupNameSnapshots.has(group) ? groupNameSnapshots.get(group) : String(group.name || '');
            const newName = options.newName;
            group.name = newName;

            if (oldName === newName) return;

            (Array.isArray(options.groups) ? options.groups : []).forEach((item) => {
                replaceNameInList(item && item.proxies, oldName, newName);
            });

            replaceProviderDialerRefs(options.providers, oldName, newName);
            replaceRuleProviderProxyRefs(options.ruleProviders, oldName, newName);

            (Array.isArray(options.proxies) ? options.proxies : []).forEach((px) => {
                replaceDialerProxyName(px, oldName, newName);
            });

            replaceRuleTargets(options.rules, oldName, newName);

            if (Array.isArray(group.proxies)) {
                group.proxies = group.proxies.filter((name) => String(name || '').trim() !== String(group.name || '').trim());
            }
            groupNameSnapshots.set(group, String(newName || ''));
        };

        return Object.freeze({
            ensureSnapshots,
            updateProviderName,
            updateProxyName,
            updateGroupName
        });
    };

    window.MihomoCore.ProviderRenameModel = Object.freeze({
        replaceNameInList,
        replaceDialerProxyName,
        replaceProviderDialerRefs,
        replaceRuleProviderProxyRefs,
        replaceProviderInlineProxyRefs,
        replaceProviderSourceRefs,
        replaceRuleTargets,
        createProviderRenameTracker
    });
})(window);
