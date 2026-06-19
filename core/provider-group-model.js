(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};

    const BUILTIN_PROXY_TARGETS = Object.freeze(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'COMPATIBLE']);

    const normalizeName = (value) => String(value || '').trim();

    const getManualProxyNames = (proxies = []) => (Array.isArray(proxies) ? proxies : [])
        .map((p) => normalizeName(p && p.name))
        .filter(Boolean);

    const getProxyGroupNames = (groups = [], currentGroupName = '') => (Array.isArray(groups) ? groups : [])
        .map((group) => normalizeName(group && group.name))
        .filter((name) => name && name !== currentGroupName);

    const getValidStaticGroupMemberNames = (options = {}) => {
        const names = new Set(BUILTIN_PROXY_TARGETS);
        getManualProxyNames(options.proxies).forEach((name) => names.add(name));
        getProxyGroupNames(options.groups, options.currentGroupName).forEach((name) => names.add(name));
        return names;
    };

    const getAvailableGroupMembers = (options = {}) => [
        ...BUILTIN_PROXY_TARGETS,
        ...getProxyGroupNames(options.groups, options.currentGroupName),
        ...getManualProxyNames(options.proxies)
    ];

    const getAvailableEmptyFallbackMembers = (proxies = []) => [
        ...BUILTIN_PROXY_TARGETS,
        ...getManualProxyNames(proxies)
    ];

    const orderAvailableNames = (available = [], selectedNames = []) => {
        if (!Array.isArray(selectedNames) || selectedNames.length === 0) return available;

        const availableMap = new Map(available.map((name) => [normalizeName(name), name]));
        const selected = [];
        const selectedSet = new Set();

        selectedNames.forEach((name) => {
            const key = normalizeName(name);
            if (!key || selectedSet.has(key) || !availableMap.has(key)) return;
            selectedSet.add(key);
            selected.push(availableMap.get(key));
        });

        const rest = available.filter((name) => !selectedSet.has(normalizeName(name)));
        return [...selected, ...rest];
    };

    const getOrderedAvailableGroupMembers = (options = {}) => {
        const available = getAvailableGroupMembers({
            proxies: options.proxies,
            groups: options.groups,
            currentGroupName: options.group && options.group.name
        });
        const selectedNames = options.group && Array.isArray(options.group.proxies) ? options.group.proxies : [];
        return orderAvailableNames(available, selectedNames);
    };

    const getProviderNames = (providers = []) => (Array.isArray(providers) ? providers : [])
        .map((p) => p && p.name)
        .filter(Boolean);

    const getOrderedGroupUseProviders = (options = {}) => {
        const available = getProviderNames(options.providers);
        const selectedNames = options.group && Array.isArray(options.group.use) ? options.group.use : [];
        return orderAvailableNames(available, selectedNames);
    };

    const pruneInvalidGroupProxyMembers = (options = {}) => {
        const groups = options.groups;
        if (!Array.isArray(groups)) return;

        groups.forEach((g) => {
            if (!Array.isArray(g.proxies)) {
                g.proxies = [];
                return;
            }

            const validNames = getValidStaticGroupMemberNames({
                proxies: options.proxies,
                groups,
                currentGroupName: g.name
            });
            const next = g.proxies.filter((name) => validNames.has(normalizeName(name)));

            if (next.length !== g.proxies.length) {
                g.proxies = next;
            }
        });
    };

    const pruneInvalidGroupUseMembers = (options = {}) => {
        const groups = options.groups;
        if (!Array.isArray(groups)) return;

        const validProviders = new Set(getProviderNames(options.providers).map(normalizeName));

        groups.forEach((g) => {
            if (!Array.isArray(g.use)) {
                g.use = [];
                return;
            }

            const next = g.use.filter((name) => validProviders.has(normalizeName(name)));
            if (next.length !== g.use.length) {
                g.use = next;
            }
        });
    };

    const groupIncludesAllProxies = (g) => !!(g && (g['include-all'] || g['include-all-proxies']));
    const groupIncludesAllProviders = (g) => !!(g && (g['include-all'] || g['include-all-providers']));

    window.MihomoCore.ProviderGroupModel = Object.freeze({
        BUILTIN_PROXY_TARGETS,
        getManualProxyNames,
        getProxyGroupNames,
        getValidStaticGroupMemberNames,
        getAvailableGroupMembers,
        getAvailableEmptyFallbackMembers,
        orderAvailableNames,
        getOrderedAvailableGroupMembers,
        getOrderedGroupUseProviders,
        pruneInvalidGroupProxyMembers,
        pruneInvalidGroupUseMembers,
        groupIncludesAllProxies,
        groupIncludesAllProviders
    });
})(window);
