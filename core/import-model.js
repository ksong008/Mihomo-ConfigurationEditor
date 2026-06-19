(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};

    const createImportModel = (options = {}) => {
        const parseYamlMapText = typeof options.parseYamlMapText === 'function'
            ? options.parseYamlMapText
            : () => ({});
        const parseYamlSequenceText = typeof options.parseYamlSequenceText === 'function'
            ? options.parseYamlSequenceText
            : () => [];
        const parseYamlObjectText = typeof options.parseYamlObjectText === 'function'
            ? options.parseYamlObjectText
            : () => ({});
        const formatYamlSequenceText = typeof options.formatYamlSequenceText === 'function'
            ? options.formatYamlSequenceText
            : (value) => JSON.stringify(value || [], null, 2);
        const formatYamlObjectText = typeof options.formatYamlObjectText === 'function'
            ? options.formatYamlObjectText
            : (value) => JSON.stringify(value || {}, null, 2);
        const normalizeTunnelListenerNetwork = typeof options.normalizeTunnelListenerNetwork === 'function'
            ? options.normalizeTunnelListenerNetwork
            : (value) => Array.isArray(value) ? value : [];

        const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);

        const safeJsonClone = (value, fallback = {}) => {
            try {
                return JSON.parse(JSON.stringify(value));
            } catch (err) {
                return fallback;
            }
        };

        const splitConfigLine = (line) => {
            const text = String(line || '').trim();
            if (!text) return ['', ''];

            let idx = text.indexOf(': ');
            if (idx < 0) idx = text.indexOf(':');
            if (idx < 0) return [text, ''];

            const offset = text[idx + 1] === ' ' ? 2 : 1;
            return [text.slice(0, idx).trim(), text.slice(idx + offset).trim()];
        };

        const ensureArray = (value) => {
            if (Array.isArray(value)) return value;
            if (value === undefined || value === null || value === '' || value === false) return [];
            if (isPlainObject(value)) return Object.values(value);
            return [value];
        };

        const ensureStringArray = (value) => {
            if (Array.isArray(value)) {
                return value
                    .map((item) => String(item ?? '').trim())
                    .filter(Boolean);
            }
            if (typeof value === 'string') {
                return value
                    .split(/\r?\n/)
                    .map((line) => line.trim())
                    .filter((line) => line && !line.startsWith('#'));
            }
            if (value === undefined || value === null || value === '' || value === false) return [];
            return [String(value).trim()].filter(Boolean);
        };

        const normalizeYamlMapLike = (value) => {
            if (isPlainObject(value)) return safeJsonClone(value, {});
            if (value === undefined || value === null || value === '' || value === false) return {};

            const text = typeof value === 'string'
                ? value
                : ensureStringArray(value).join('\n');
            if (!text.trim()) return {};

            const parsed = parseYamlMapText(text);
            return parsed || {};
        };

        const normalizeProxyNameRuleItem = (item) => {
            if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
            const pattern = String(item.pattern ?? '').trim();
            const target = String(item.target ?? '').trim();
            if (!pattern || !target) return null;
            return { pattern, target };
        };

        const normalizeProxyNameRules = (value) => {
            if (Array.isArray(value)) {
                return value
                    .map(normalizeProxyNameRuleItem)
                    .filter(Boolean);
            }

            if (isPlainObject(value)) {
                const item = normalizeProxyNameRuleItem(value);
                return item ? [item] : [];
            }

            if (value === undefined || value === null || value === '' || value === false) return [];

            try {
                return parseYamlSequenceText(String(value), normalizeProxyNameRuleItem) || [];
            } catch (err) {
                return [];
            }
        };
        const normalizeProviderOverrideBooleanValue = (value) => {
            if (value === true) return true;
            if (value === false) return false;
            return value;
        };
        const formatProviderOverrideBooleanValue = (value) => {
            if (value === true) return 'true';
            if (value === false) return 'false';
            return '';
        };
        const normalizeProviderOverrideScalar = (value) => {
            if (value === undefined || value === null || value === '') return '';
            if (Array.isArray(value) || isPlainObject(value)) return value;
            return String(value).trim();
        };

        const normalizeImportedHosts = (value) => {
            if (isPlainObject(value)) return value;

            const result = {};
            ensureArray(value).forEach((item) => {
                if (Array.isArray(item) && item.length >= 2) {
                    const key = String(item[0] ?? '').trim();
                    const val = String(item[1] ?? '').trim();
                    if (key && val) result[key] = val;
                    return;
                }

                const [key, val] = splitConfigLine(item);
                if (key && val) result[key] = val;
            });
            return result;
        };

        const normalizeRuleLine = (rule) => {
            if (typeof rule === 'string') {
                const text = rule.trim();
                return text && !text.startsWith('#') ? text : '';
            }

            if (Array.isArray(rule)) {
                const parts = rule.map((item) => String(item ?? '').trim()).filter(Boolean);
                return parts.join(',');
            }

            if (!isPlainObject(rule)) return '';

            const type = String(rule.type || '').trim();
            if (!type) return '';

            if (type === 'MATCH') {
                return rule.target ? `MATCH,${rule.target}` : 'MATCH';
            }

            const parts = [type];
            const value = rule.value !== undefined && rule.value !== null ? String(rule.value) : '';
            if (value !== '') parts.push(value);

            if (rule.target !== undefined && rule.target !== null && String(rule.target).trim() !== '') {
                parts.push(String(rule.target).trim());
            }

            if (rule.noResolve) parts.push('no-resolve');
            if (rule.src !== undefined && rule.src !== null && String(rule.src).trim() !== '') {
                parts.push('src', String(rule.src).trim());
            }
            return parts.join(',');
        };

        const listToMultilineText = (value) => {
            if (Array.isArray(value)) {
                return value.map((item) => String(item ?? '').trim()).filter(Boolean).join('\n');
            }
            if (typeof value === 'string') return value.trim();
            if (value === undefined || value === null || value === false) return '';
            return String(value).trim();
        };

        const normalizeImportedMap = (value, prefix) => {
            const result = {};

            if (isPlainObject(value)) {
                Object.keys(value).forEach((key) => {
                    const item = value[key];
                    if (!isPlainObject(item)) return;
                    result[key] = { ...item };
                });
                return result;
            }

            ensureArray(value).forEach((item, idx) => {
                if (!isPlainObject(item)) return;
                const name = String(item.name || item.tag || `${prefix}-${idx + 1}`).trim();
                result[name] = { ...item };
            });

            return result;
        };

        const normalizeImportedConfigData = (source) => {
            const data = isPlainObject(source) ? safeJsonClone(source, {}) : {};

            const supportedProxyProviderTypes = new Set(['http', 'file', 'inline']);
            const supportedRuleProviderTypes = new Set(['http', 'file', 'inline']);
            const supportedProxyGroupTypes = new Set(['select', 'url-test', 'fallback', 'load-balance', 'relay']);

            if (data.tun !== undefined && data.tun !== false && !isPlainObject(data.tun)) data.tun = {};
            if (data.sniffer !== undefined && data.sniffer !== false && !isPlainObject(data.sniffer)) data.sniffer = {};
            if (data.dns !== undefined && data.dns !== false && !isPlainObject(data.dns)) data.dns = {};

            if (data.listeners !== undefined) {
                data.listeners = ensureArray(data.listeners)
                    .filter(isPlainObject)
                    .map((item, idx) => {
                        const users = ensureArray(item.users).filter(isPlainObject);
                        return {
                            ...item,
                            name: String(item.name || `listener-${idx + 1}`).trim() || `listener-${idx + 1}`,
                            rule: String(item.rule || ''),
                            proxy: String(item.proxy || ''),
                            token: String(item.token || ''),
                            cipher: String(item.cipher || ''),
                            password: String(item.password || ''),
                            network: normalizeTunnelListenerNetwork(item.network),
                            target: String(item.target || ''),
                            certificate: String(item.certificate || ''),
                            'private-key': String(item['private-key'] || ''),
                            'client-auth-type': String(item['client-auth-type'] || ''),
                            'client-auth-cert': String(item['client-auth-cert'] || ''),
                            'ech-key': String(item['ech-key'] || ''),
                            'ech-cert': String(item['ech-cert'] || ''),
                            ...(item['allow-insecure'] !== undefined ? { 'allow-insecure': item['allow-insecure'] === true } : {}),
                            users,
                            _usersText: formatYamlSequenceText(users),
                            _shadowTlsText: formatYamlObjectText(item['shadow-tls']),
                            _kcpTunText: formatYamlObjectText(item['kcp-tun'])
                        };
                    });
            }

            ['lan-allowed-ips', 'lan-disallowed-ips', 'authentication', 'skip-auth-prefixes'].forEach((key) => {
                if (data[key] !== undefined) {
                    data[key] = ensureStringArray(data[key]);
                }
            });

            if (data['external-controller-cors'] !== undefined && !isPlainObject(data['external-controller-cors'])) {
                data['external-controller-cors'] = normalizeYamlMapLike(data['external-controller-cors']);
            }

            if (data.tls !== undefined && !isPlainObject(data.tls)) {
                data.tls = normalizeYamlMapLike(data.tls);
            }

            if (data['sub-rules'] !== undefined && !isPlainObject(data['sub-rules'])) {
                data['sub-rules'] = parseYamlObjectText(typeof data['sub-rules'] === 'string' ? data['sub-rules'] : JSON.stringify(data['sub-rules']));
            }

            if (data.experimental !== undefined && !isPlainObject(data.experimental)) {
                data.experimental = normalizeYamlMapLike(data.experimental);
            }

            if (data.proxies !== undefined) {
                const importedGlobalFingerprint = String(data['global-client-fingerprint'] || '').trim();
                const fingerprintProxyTypes = new Set(['vless', 'vmess', 'trojan', 'anytls', 'trusttunnel']);
                data.proxies = ensureArray(data.proxies)
                    .filter(isPlainObject)
                    .map((item, idx) => {
                        const type = String(item.type || 'vless').trim() || 'vless';
                        const next = {
                            ...item,
                            name: String(item.name || item.server || `Node-${idx + 1}`).trim() || `Node-${idx + 1}`,
                            type
                        };
                        if (importedGlobalFingerprint && fingerprintProxyTypes.has(type) && !String(next['client-fingerprint'] || '').trim()) {
                            next['client-fingerprint'] = importedGlobalFingerprint;
                        }
                        return next;
                    });
            }

            if (data['proxy-groups'] !== undefined) {
                data['proxy-groups'] = ensureArray(data['proxy-groups'])
                    .filter(isPlainObject)
                    .map((g, idx) => {
                        const type = String(g.type || 'select').trim();
                        return {
                            ...g,
                            name: String(g.name || `Group-${idx + 1}`).trim() || `Group-${idx + 1}`,
                            type: supportedProxyGroupTypes.has(type) ? type : 'select',
                            proxies: ensureStringArray(g.proxies),
                            use: ensureStringArray(g.use),
                            filter: String(g.filter || ''),
                            'exclude-filter': String(g['exclude-filter'] || ''),
                            'exclude-type': String(g['exclude-type'] || ''),
                            url: String(g.url || 'https://www.gstatic.com/generate_204'),
                            interval: Number(g.interval) > 0 ? Number(g.interval) : 300,
                            tolerance: Number.isFinite(Number(g.tolerance)) ? Number(g.tolerance) : 50,
                            timeout: Number.isFinite(Number(g.timeout)) ? Number(g.timeout) : 0,
                            lazy: g.lazy !== false,
                            'max-failed-times': Number.isFinite(Number(g['max-failed-times'])) ? Number(g['max-failed-times']) : 5,
                            'disable-udp': g['disable-udp'] === true,
                            'interface-name': String(g['interface-name'] || ''),
                            'routing-mark': g['routing-mark'] !== undefined && g['routing-mark'] !== null ? String(g['routing-mark']) : '',
                            strategy: String(g.strategy || 'consistent-hashing'),
                            'include-all': g['include-all'] === true,
                            'include-all-proxies': g['include-all-proxies'] === true,
                            'include-all-providers': g['include-all-providers'] === true,
                            'expected-status': String(g['expected-status'] || ''),
                            'empty-fallback': String(g['empty-fallback'] || ''),
                            hidden: g.hidden === true,
                            icon: String(g.icon || '')
                        };
                    });
            }

            if (data.rules !== undefined) {
                data.rules = ensureArray(data.rules)
                    .map(normalizeRuleLine)
                    .filter(Boolean);
            }

            if (data.sniffer && isPlainObject(data.sniffer)) {
                ['skip-domain', 'force-domain', 'port-whitelist', 'skip-src-address', 'skip-dst-address'].forEach((key) => {
                    if (data.sniffer[key] !== undefined) {
                        data.sniffer[key] = ensureStringArray(data.sniffer[key]);
                    }
                });

                if (data.sniffer.sniff && isPlainObject(data.sniffer.sniff)) {
                    ['HTTP', 'TLS', 'QUIC'].forEach((proto) => {
                        const item = data.sniffer.sniff[proto];
                        if (item && isPlainObject(item) && item.ports !== undefined) {
                            item.ports = ensureStringArray(item.ports);
                        }
                    });
                }
            }

            if (data.dns && isPlainObject(data.dns)) {
                ['fake-ip-filter', 'default-nameserver', 'nameserver', 'fallback', 'proxy-server-nameserver', 'direct-nameserver'].forEach((key) => {
                    if (data.dns[key] !== undefined) {
                        data.dns[key] = ensureStringArray(data.dns[key]);
                    }
                });

                if (data.dns['fallback-filter'] && isPlainObject(data.dns['fallback-filter'])) {
                    ['geosite', 'ipcidr', 'domain'].forEach((key) => {
                        if (data.dns['fallback-filter'][key] !== undefined) {
                            data.dns['fallback-filter'][key] = ensureStringArray(data.dns['fallback-filter'][key]);
                        }
                    });
                }

                if (data.dns['nameserver-policy'] !== undefined && !isPlainObject(data.dns['nameserver-policy'])) {
                    const normalizedPolicyText = ensureStringArray(data.dns['nameserver-policy']).join('\n');
                    const parsedPolicy = parseYamlMapText(normalizedPolicyText);
                    data.dns['nameserver-policy'] = parsedPolicy || {};
                }

                if (data.dns['proxy-server-nameserver-policy'] !== undefined && !isPlainObject(data.dns['proxy-server-nameserver-policy'])) {
                    const normalizedPolicyText = ensureStringArray(data.dns['proxy-server-nameserver-policy']).join('\n');
                    const parsedPolicy = parseYamlMapText(normalizedPolicyText);
                    data.dns['proxy-server-nameserver-policy'] = parsedPolicy || {};
                }
            }

            if (data.tun && isPlainObject(data.tun)) {
                [
                    'dns-hijack',
                    'route-address-set',
                    'route-exclude-address-set',
                    'route-address',
                    'route-exclude-address',
                    'include-interface',
                    'exclude-interface',
                    'include-uid',
                    'include-uid-range',
                    'exclude-uid',
                    'exclude-uid-range',
                    'include-android-user',
                    'include-package',
                    'exclude-package'
                ].forEach((key) => {
                    if (data.tun[key] !== undefined) {
                        data.tun[key] = ensureStringArray(data.tun[key]);
                    }
                });
            }

            if (data.hosts !== undefined) {
                data.hosts = normalizeImportedHosts(data.hosts);
            }

            if (data['proxy-providers'] !== undefined) {
                const rawProviders = normalizeImportedMap(data['proxy-providers'], 'provider');
                const nextProviders = {};

                Object.keys(rawProviders).forEach((key, idx) => {
                    const p = rawProviders[key];
                    if (!p || !isPlainObject(p)) return;

                    const type = String(p.type || 'http').trim() || 'http';
                    if (!supportedProxyProviderTypes.has(type)) return;

                    const name = String(key || p.name || `provider-${idx + 1}`).trim() || `provider-${idx + 1}`;
                    const providerPayload = ensureArray(p.payload)
                        .filter(isPlainObject)
                        .map((item) => safeJsonClone(item, {}))
                        .filter((item) => isPlainObject(item));

                    const next = {
                        ...p,
                        type,
                        path: String(p.path || ''),
                        proxy: String(p.proxy || p['dialer-proxy'] || ''),
                        'age-secret-key': String(p['age-secret-key'] || ''),
                        header: normalizeYamlMapLike(p.header),
                        filter: String(p.filter || ''),
                        'exclude-filter': String(p['exclude-filter'] || ''),
                        'exclude-type': String(p['exclude-type'] || '')
                    };

                    if (p['size-limit'] !== undefined && p['size-limit'] !== null && p['size-limit'] !== '') {
                        const sizeLimit = Number(p['size-limit']);
                        if (Number.isFinite(sizeLimit) && sizeLimit >= 0) next['size-limit'] = sizeLimit;
                    }

                    const rawOverride = isPlainObject(p.override) ? { ...p.override } : {};
                    next.override = {
                        ...rawOverride,
                        'dialer-proxy': String(rawOverride['dialer-proxy'] || ''),
                        'additional-prefix': String(rawOverride['additional-prefix'] || ''),
                        'additional-suffix': String(rawOverride['additional-suffix'] || ''),
                        'proxy-name': normalizeProxyNameRules(rawOverride['proxy-name']),
                        udp: normalizeProviderOverrideBooleanValue(rawOverride.udp),
                        'udp-over-tcp': normalizeProviderOverrideBooleanValue(rawOverride['udp-over-tcp']),
                        tfo: normalizeProviderOverrideBooleanValue(rawOverride.tfo),
                        mptcp: normalizeProviderOverrideBooleanValue(rawOverride.mptcp),
                        'skip-cert-verify': normalizeProviderOverrideBooleanValue(rawOverride['skip-cert-verify']),
                        up: normalizeProviderOverrideScalar(rawOverride.up),
                        down: normalizeProviderOverrideScalar(rawOverride.down),
                        'interface-name': normalizeProviderOverrideScalar(rawOverride['interface-name']),
                        'routing-mark': normalizeProviderOverrideScalar(rawOverride['routing-mark']),
                        'ip-version': normalizeProviderOverrideScalar(rawOverride['ip-version'])
                    };

                    if (type === 'http') {
                        next.url = String(p.url || '');
                        next.interval = Number(p.interval) > 0 ? Number(p.interval) : 3600;
                    } else if (type === 'file') {
                        next.interval = Number(p.interval) > 0 ? Number(p.interval) : 3600;
                    } else if (type === 'inline') {
                        next.payload = providerPayload;
                    }

                    if ((type === 'http' || type === 'file') && providerPayload.length > 0) {
                        next.payload = providerPayload;
                    }

                    if (type === 'http' || type === 'file') {
                        const healthCheck = isPlainObject(p['health-check']) ? { ...p['health-check'] } : {};
                        next['health-check'] = {
                            enable: healthCheck.enable !== false,
                            url: String(healthCheck.url || ''),
                            interval: Number(healthCheck.interval) > 0 ? Number(healthCheck.interval) : 600,
                            timeout: Number(healthCheck.timeout) > 0 ? Number(healthCheck.timeout) : 5000,
                            lazy: healthCheck.lazy !== false
                        };
                        if (healthCheck['expected-status'] !== undefined && healthCheck['expected-status'] !== null && String(healthCheck['expected-status']).trim() !== '') {
                            next['health-check']['expected-status'] = String(healthCheck['expected-status']).trim();
                        }
                    }

                    nextProviders[name] = next;
                });

                data['proxy-providers'] = nextProviders;
            }

            if (data['rule-providers'] !== undefined) {
                const rawRuleProviders = normalizeImportedMap(data['rule-providers'], 'rule-provider');
                const nextRuleProviders = {};

                Object.keys(rawRuleProviders).forEach((key, idx) => {
                    const p = rawRuleProviders[key];
                    if (!p || !isPlainObject(p)) return;

                    const type = String(p.type || 'http').trim() || 'http';
                    if (!supportedRuleProviderTypes.has(type)) return;

                    const name = String(key || p.name || `rule-provider-${idx + 1}`).trim() || `rule-provider-${idx + 1}`;
                    const next = {
                        ...p,
                        type,
                        behavior: String(p.behavior || 'domain'),
                        format: String(p.format || 'mrs'),
                        proxy: String(p.proxy || ''),
                        'path-in-bundle': String(p['path-in-bundle'] || ''),
                        header: normalizeYamlMapLike(p.header)
                    };

                    if (p['size-limit'] !== undefined && p['size-limit'] !== null && p['size-limit'] !== '') {
                        const sizeLimit = Number(p['size-limit']);
                        if (Number.isFinite(sizeLimit) && sizeLimit >= 0) next['size-limit'] = sizeLimit;
                    }

                    if (type === 'inline') next.payload = ensureStringArray(p.payload);
                    if (type === 'file') next.path = String(p.path || '');
                    if (type === 'http') {
                        next.url = String(p.url || '');
                        next.path = String(p.path || '');
                        next.interval = Number(p.interval) > 0 ? Number(p.interval) : 86400;
                    }

                    nextRuleProviders[name] = next;
                });

                data['rule-providers'] = nextRuleProviders;
            }

            return data;
        };

        return {
            isPlainObject,
            safeJsonClone,
            ensureArray,
            normalizeImportedConfigData,
            listToMultilineText,
            formatProviderOverrideBooleanValue
        };
    };

    window.MihomoCore.ImportModel = Object.freeze({
        createImportModel
    });
})(window);
