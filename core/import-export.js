(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createImportExportModule = function (ctx) {
        const {
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
        } = ctx;
        const { getListenPort, parseYamlMapText } = window.MihomoHelpers;

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
            return parts.join(',');
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

            const supportedProxyProviderTypes = new Set(['http', 'inline']);
            const supportedRuleProviderTypes = new Set(['http', 'file', 'inline']);
            const supportedProxyGroupTypes = new Set(['select', 'url-test', 'fallback', 'load-balance', 'relay']);

            if (data.tun !== undefined && data.tun !== false && !isPlainObject(data.tun)) data.tun = {};
            if (data.sniffer !== undefined && data.sniffer !== false && !isPlainObject(data.sniffer)) data.sniffer = {};
            if (data.dns !== undefined && data.dns !== false && !isPlainObject(data.dns)) data.dns = {};

            if (data.listeners !== undefined) {
                data.listeners = ensureArray(data.listeners)
                    .filter(isPlainObject)
                    .map((item, idx) => ({
                        ...item,
                        name: String(item.name || `listener-${idx + 1}`).trim() || `listener-${idx + 1}`
                    }));
            }

            if (data.proxies !== undefined) {
                data.proxies = ensureArray(data.proxies)
                    .filter(isPlainObject)
                    .map((item, idx) => ({
                        ...item,
                        name: String(item.name || item.server || `Node-${idx + 1}`).trim() || `Node-${idx + 1}`,
                        type: String(item.type || 'vless').trim() || 'vless'
                    }));
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
                            url: String(g.url || 'https://www.gstatic.com/generate_204'),
                            interval: Number(g.interval) > 0 ? Number(g.interval) : 300,
                            tolerance: Number.isFinite(Number(g.tolerance)) ? Number(g.tolerance) : 50,
                            timeout: Number.isFinite(Number(g.timeout)) ? Number(g.timeout) : 0,
                            lazy: g.lazy !== false,
                            'dialer-proxy': String(g['dialer-proxy'] || ''),
                            strategy: String(g.strategy || 'consistent-hashing'),
                            'include-all': g['include-all'] === true
                        };
                    });
            }

            if (data.rules !== undefined) {
                data.rules = ensureArray(data.rules)
                    .map(normalizeRuleLine)
                    .filter(Boolean);
            }

            if (data.sniffer && isPlainObject(data.sniffer)) {
                ['skip-domain', 'force-domain', 'port-whitelist'].forEach((key) => {
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
                    const next = { ...p, type };

                    if (type === 'http') {
                        next.url = String(p.url || '');
                        next.interval = Number(p.interval) > 0 ? Number(p.interval) : 3600;
                        next['health-check'] = isPlainObject(p['health-check']) ? { ...p['health-check'] } : {};
                        next['dialer-proxy'] = String(p['dialer-proxy'] || '');
                    } else if (type === 'inline') {
                        next.payload = ensureArray(p.payload).filter(isPlainObject);
                        next.override = isPlainObject(p.override) ? { ...p.override } : {};
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
                        format: String(p.format || 'yaml')
                    };

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

        const createStateSnapshot = () => ({
            config: safeJsonClone(config.value, getDefaultConfig()),
            uiState: safeJsonClone(uiState.value, {}),
            providersList: safeJsonClone(providersList.value, []),
            ruleProvidersList: safeJsonClone(ruleProvidersList.value, [])
        });

        const restoreStateSnapshot = (snapshot) => {
            if (!snapshot) return;

            config.value = safeJsonClone(snapshot.config, getDefaultConfig());
            uiState.value = safeJsonClone(snapshot.uiState, {});
            providersList.value = ensureArray(snapshot.providersList).filter(isPlainObject);
            ruleProvidersList.value = ensureArray(snapshot.ruleProvidersList).filter(isPlainObject);

            ensureGroupCollapseState();
            ensureRuleProviderCollapseState();
            pruneInvalidGroupProxyMembers();
            pruneInvalidGroupUseMembers();
        };

        const resolveYamlMergeKeys = (obj) => {
            if (!obj || typeof obj !== 'object') return obj;
            if (Array.isArray(obj)) return obj.map(resolveYamlMergeKeys);

            const result = {};
            for (const key in obj) {
                if (key === '<<' && typeof obj[key] === 'object') {
                    const merged = resolveYamlMergeKeys(obj[key]);
                    Object.assign(result, merged);
                } else {
                    result[key] = resolveYamlMergeKeys(obj[key]);
                }
            }
            return result;
        };

        const triggerYamlImport = () => {
            fileInput.value.click();
        };

        const applyYamlImport = (data) => {
            if (!data) return;
            data = normalizeImportedConfigData(data);

            if (data['mixed-port'] !== undefined) config.value['mixed-port'] = data['mixed-port'];
            if (data.port !== undefined) config.value.port = data.port;
            if (data['socks-port'] !== undefined) config.value['socks-port'] = data['socks-port'];
            if (data['redir-port'] !== undefined) config.value['redir-port'] = data['redir-port'];

            if (data['tproxy-port'] !== undefined && data['tproxy-port'] > 0) {
                config.value['tproxy-port'] = data['tproxy-port'];
                uiState.value.tproxyEnable = true;
                uiState.value.nftablesConfig.tproxyPort = data['tproxy-port'];
            } else {
                uiState.value.tproxyEnable = false;
            }

            if (data['geox-url']) config.value.geo.url = { ...config.value.geo.url, ...data['geox-url'] };
            if (data['geo-auto-update'] !== undefined) config.value.geo['auto-update'] = data['geo-auto-update'];
            if (data['geo-update-interval'] !== undefined) config.value.geo.interval = data['geo-update-interval'];

            if (data['routing-mark'] !== undefined) {
                config.value['routing-mark'] = data['routing-mark'];
                uiState.value.nftablesConfig.routeMarkHex = String(data['routing-mark']);
            }

            if (data['interface-name'] !== undefined) {
                config.value['interface-name'] = data['interface-name'];
                if (uiState.value.nftablesConfig) uiState.value.nftablesConfig.egressIface = data['interface-name'] || '';
            }
            if (data['geodata-mode'] !== undefined) config.value['geodata-mode'] = data['geodata-mode'];
            if (data['unified-delay'] !== undefined) config.value['unified-delay'] = data['unified-delay'];
            if (data['tcp-concurrent'] !== undefined) config.value['tcp-concurrent'] = data['tcp-concurrent'];
            if (data['global-client-fingerprint'] !== undefined) config.value['global-client-fingerprint'] = data['global-client-fingerprint'];

            let finalListeners = [];
            if (data.listeners && Array.isArray(data.listeners)) {
                finalListeners = data.listeners.map(l => ({ ...l }));
            }

            const tpIndex = finalListeners.findIndex(l => l.type === 'tproxy');
            if (tpIndex > -1) {
                const tp = finalListeners[tpIndex];
                uiState.value.tproxyEnable = true;
                config.value['tproxy-port'] = tp.port || 7894;
                uiState.value.nftablesConfig.tproxyPort = tp.port || 7894;
                uiState.value.nftablesConfig.listen = tp.listen || '0.0.0.0';
                uiState.value.nftablesConfig.udp = tp.udp !== false;
            }
            config.value.listeners = finalListeners;

            if (data['allow-lan'] !== undefined) config.value['allow-lan'] = data['allow-lan'];
            if (data.mode !== undefined) config.value.mode = data.mode;
            if (data['log-level'] !== undefined) config.value['log-level'] = data['log-level'];
            if (data.ipv6 !== undefined) config.value.ipv6 = data.ipv6;
            if (data['find-process-mode'] !== undefined) config.value['find-process-mode'] = data['find-process-mode'];
            if (data.profile) config.value.profile = { ...config.value.profile, ...data.profile };
            if (data['external-controller']) config.value['external-controller'] = data['external-controller'];
            if (data.secret) config.value.secret = data.secret;
            if (data['external-ui']) config.value['external-ui'] = data['external-ui'];
            if (data['external-ui-url']) config.value['external-ui-url'] = data['external-ui-url'];

            if (data.tun) {
                config.value.tun = { ...config.value.tun, enable: true, ...data.tun };
                if (data.tun['dns-hijack'] && Array.isArray(data.tun['dns-hijack']) && data.tun['dns-hijack'].length > 0) {
                    uiState.value.tunDnsHijackEnabled = true;
                    uiState.value.tunDnsHijack = data.tun['dns-hijack'].join('\n');
                } else if (typeof data.tun['dns-hijack'] === 'string' && data.tun['dns-hijack'].trim()) {
                    uiState.value.tunDnsHijackEnabled = true;
                    uiState.value.tunDnsHijack = data.tun['dns-hijack'].trim();
                } else {
                    uiState.value.tunDnsHijackEnabled = false;
                }
            } else {
                config.value.tun.enable = false;
                uiState.value.tunDnsHijackEnabled = false;
            }

            if (data.sniffer) {
                config.value.sniffer.enable = true;
                if (data.sniffer['force-dns-mapping'] !== undefined) config.value.sniffer['force-dns-mapping'] = data.sniffer['force-dns-mapping'];
                if (data.sniffer['parse-pure-ip'] !== undefined) config.value.sniffer['parse-pure-ip'] = data.sniffer['parse-pure-ip'];
                if (data.sniffer['override-destination'] !== undefined) config.value.sniffer['override-destination'] = data.sniffer['override-destination'];

                uiState.value.snifferSniff = { HTTP: '', TLS: '', QUIC: '' };
                if (data.sniffer.sniff) {
                    if (data.sniffer.sniff.HTTP && data.sniffer.sniff.HTTP.ports) uiState.value.snifferSniff.HTTP = data.sniffer.sniff.HTTP.ports.join(', ');
                    if (data.sniffer.sniff.TLS && data.sniffer.sniff.TLS.ports) uiState.value.snifferSniff.TLS = data.sniffer.sniff.TLS.ports.join(', ');
                    if (data.sniffer.sniff.QUIC && data.sniffer.sniff.QUIC.ports) uiState.value.snifferSniff.QUIC = data.sniffer.sniff.QUIC.ports.join(', ');
                }

                if (data.sniffer['skip-domain']) uiState.value.snifferSkipDomain = data.sniffer['skip-domain'].join('\n');
                if (data.sniffer['force-domain']) uiState.value.snifferForceDomain = data.sniffer['force-domain'].join('\n');
                if (data.sniffer['port-whitelist']) uiState.value.snifferPortWhitelist = data.sniffer['port-whitelist'].join('\n');
            } else {
                config.value.sniffer.enable = false;
            }

            if (data.dns) {
                config.value.dns.enable = true;
                ['listen', 'ipv6', 'enhanced-mode', 'fake-ip-range', 'fake-ip-filter-mode', 'prefer-h3', 'respect-rules', 'use-hosts', 'use-system-hosts', 'direct-nameserver-follow-policy'].forEach(k => {
                    if (data.dns[k] !== undefined) config.value.dns[k] = data.dns[k];
                });
                config.value.dns.listen = String(getListenPort(config.value.dns.listen, 53));

                if (data.dns['fake-ip-filter']) uiState.value.fakeIpFilter = data.dns['fake-ip-filter'].join('\n');
                if (data.dns['default-nameserver']) uiState.value.dnsDefaultNameservers = data.dns['default-nameserver'].join('\n');
                if (data.dns.nameserver) uiState.value.dnsNameservers = data.dns.nameserver.join('\n');

                const importedFallback = Array.isArray(data.dns.fallback)
                    ? data.dns.fallback
                    : (typeof data.dns.fallback === 'string' && data.dns.fallback.trim() ? [data.dns.fallback.trim()] : []);
                if (importedFallback.length > 0) {
                    uiState.value.enableDnsFallback = true;
                    uiState.value.dnsFallback = importedFallback.join('\n');
                } else {
                    uiState.value.enableDnsFallback = false;
                }

                if (data.dns['proxy-server-nameserver']) uiState.value.dnsProxyServerNameservers = data.dns['proxy-server-nameserver'].join('\n');
                if (data.dns['direct-nameserver']) uiState.value.dnsDirectNameservers = data.dns['direct-nameserver'].join('\n');

                if (data.dns['nameserver-policy']) {
                    uiState.value.enableNameserverPolicy = true;
                    uiState.value.dnsNameserverPolicy = formatYamlMapText(data.dns['nameserver-policy']);
                } else {
                    uiState.value.enableNameserverPolicy = false;
                    config.value.dns['direct-nameserver-follow-policy'] = false;
                    uiState.value.dnsNameserverPolicy = '';
                }

                if (data.dns['fallback-filter']) {
                    config.value.dns['fallback-filter'].geoip = data.dns['fallback-filter'].geoip !== false;
                    if (data.dns['fallback-filter']['geoip-code']) {
                        config.value.dns['fallback-filter']['geoip-code'] = data.dns['fallback-filter']['geoip-code'];
                    }

                    if (data.dns['fallback-filter'].geosite) {
                        uiState.value.fallbackFilterGeositeEnable = true;
                        uiState.value.fallbackFilterGeosite = data.dns['fallback-filter'].geosite.join('\n');
                    } else {
                        uiState.value.fallbackFilterGeositeEnable = false;
                    }

                    if (data.dns['fallback-filter'].ipcidr) uiState.value.fallbackFilterIpcidr = data.dns['fallback-filter'].ipcidr.join('\n');
                    if (data.dns['fallback-filter'].domain) uiState.value.fallbackFilterDomain = data.dns['fallback-filter'].domain.join('\n');
                }
            } else {
                config.value.dns.enable = false;
                uiState.value.enableDnsFallback = false;
            }

            if (data.hosts) {
                uiState.value.hosts = Object.keys(data.hosts)
                    .map(k => `${k}: ${data.hosts[k]}`)
                    .join('\n');
                if (config.value.dns && (!data.dns || data.dns['use-hosts'] === undefined)) {
                    config.value.dns['use-hosts'] = true;
                }
            } else {
                uiState.value.hosts = '';
            }

            if (data['proxy-providers']) {
                Object.values(data['proxy-providers']).forEach(p => {
                    if (p.type === 'inline' && Array.isArray(p.payload)) {
                        if (!data.proxies) data.proxies = [];
                        p.payload.forEach(px => {
                            if (!data.proxies.find(x => x.name === px.name)) data.proxies.push(px);
                        });
                    }
                });
            }

            if (data.proxies && Array.isArray(data.proxies)) {
                config.value.proxies = data.proxies.map(px => parseSingleProxyNode(px)).filter(Boolean);
            } else {
                config.value.proxies = [];
            }

            if (data['proxy-providers']) {
                providersList.value = Object.keys(data['proxy-providers']).map(k => {
                    const p = data['proxy-providers'][k];
                    const prov = { name: k, type: p.type || 'http', overrideDialerProxy: '', inlineProxies: [] };

                    if (prov.type === 'http') {
                        prov.url = p.url || '';
                        prov.interval = p.interval || 3600;
                        prov.lazy = p.lazy !== false;
                        prov.healthUrl = p['health-check']?.url || 'https://www.gstatic.com/generate_204';
                        prov.healthCheckLazy = p['health-check']?.lazy !== false;
                        prov.healthCheckTimeout = p['health-check']?.timeout || 5000;
                        prov.useDownloadProxy = !!p['dialer-proxy'];
                        prov.downloadProxy = p['dialer-proxy'] || '';
                    } else if (prov.type === 'inline') {
                        if (p.payload && Array.isArray(p.payload)) {
                            prov.inlineProxies = p.payload.map(px => px.name).filter(Boolean);
                        }
                        if (p.override && p.override['dialer-proxy']) {
                            prov.overrideDialerProxy = p.override['dialer-proxy'];
                        }
                    }
                    return prov;
                });
            } else {
                providersList.value = [];
            }

            if (data['rule-providers']) {
                ruleProvidersList.value = Object.keys(data['rule-providers']).map(k => {
                    const p = data['rule-providers'][k];
                    const rp = {
                        name: k,
                        type: p.type || 'http',
                        behavior: p.behavior || 'domain',
                        format: p.format || 'yaml',
                        interval: p.interval || 86400,
                        autoUrl: false,
                        customUrl: '',
                        path: p.path || '',
                        file: '',
                        payload: '',
                        _collapsed: false
                    };

                    if (rp.type === 'http') {
                        rp.customUrl = p.url || '';
                        if (rp.customUrl.includes('meta-rules-dat')) {
                            rp.autoUrl = true;
                            const parts = rp.customUrl.split('/');
                            const filename = parts[parts.length - 1];
                            rp.file = filename.substring(0, filename.lastIndexOf('.'));
                        }
                    } else if (rp.type === 'inline') {
                        rp.payload = Array.isArray(p.payload) ? p.payload.join('\n') : '';
                    } else if (rp.type === 'file') {
                        rp.path = p.path || '';
                    }
                    return rp;
                });
            } else {
                ruleProvidersList.value = [];
            }

            if (data['proxy-groups'] && Array.isArray(data['proxy-groups'])) {
                config.value['proxy-groups'] = data['proxy-groups'].map(g => {
                    return {
                        name: g.name,
                        type: g.type,
                        proxies: Array.isArray(g.proxies) ? g.proxies : [],
                        use: Array.isArray(g.use) ? g.use : [],
                        filter: g.filter || '',
                        'exclude-filter': g['exclude-filter'] || '',
                        url: g.url || 'https://www.gstatic.com/generate_204',
                        interval: g.interval || 300,
                        tolerance: g.tolerance || 50,
                        timeout: g.timeout || 0,
                        lazy: g.lazy !== false,
                        'dialer-proxy': g['dialer-proxy'] || '',
                        strategy: g.strategy || 'consistent-hashing',
                        'include-all': g['include-all'] === true,
                        _collapsed: typeof g._collapsed === 'boolean' ? g._collapsed : true
                    };
                });
            } else {
                config.value['proxy-groups'] = [];
            }

            if (data.rules && Array.isArray(data.rules)) {
                uiState.value.rules = data.rules.map(r => parseRuleString(r)).filter(Boolean);
            } else {
                uiState.value.rules = [];
            }

            scrollToBottom();
        };

        const handleYamlImport = (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;

            const snapshot = createStateSnapshot();
            const reader = new FileReader();

            reader.onload = (ev) => {
                try {
                    crashError.value = null;

                    const cleanText = String(ev.target?.result || '').replace(/\xA0/g, ' ');
                    let parsed = jsyaml.load(cleanText);
                    parsed = resolveYamlMergeKeys(parsed);

                    applyYamlImport(parsed);

                    ensureGroupCollapseState();
                    ensureRuleProviderCollapseState();
                    pruneInvalidGroupProxyMembers();
                    pruneInvalidGroupUseMembers();

                    const ok = safeBuildYaml(`导入文件: ${file.name}`);
                    if (!ok) {
                        const importErr = crashError.value;
                        crashError.value = null;

                        restoreStateSnapshot(snapshot);
                        safeBuildYaml('导入回滚后重建');

                        alert(
                            '导入失败：该 YAML 含有当前 UI 暂不支持或无法安全渲染的结构，已自动回滚，避免白屏。\n\n' +
                            (importErr || '')
                        );
                        e.target.value = '';
                        return;
                    }

                    alert('YAML 导入成功！\n注意：原配置中的高级锚点已被展开。部分复杂自定义数据可能需要手动微调。');
                } catch (err) {
                    console.error('YAML 导入失败:', err);
                    crashError.value = null;

                    restoreStateSnapshot(snapshot);
                    safeBuildYaml('导入异常回滚后重建');

                    alert('YAML 导入失败: ' + err.message);
                }

                e.target.value = '';
            };

            reader.readAsText(file);
        };

        const copyYaml = async () => {
            try {
                await navigator.clipboard.writeText(fullYaml.value);
                alert('YAML 已成功复制到剪贴板！');
            } catch (e) {
                alert('复制失败，请在右侧代码框中手动全选复制。');
            }
        };

        const normalizeDownloadFileName = (name) => {
            let fileName = String(name || uiState.value.downloadFileName || 'config.yaml').trim();
            fileName = fileName.replace(/[\\/:*?"<>|]+/g, '-');
            if (!fileName) fileName = 'config.yaml';
            if (!/\.(yaml|yml)$/i.test(fileName)) fileName += '.yaml';
            return fileName;
        };

        const downloadYaml = (fileName) => {
            const finalName = normalizeDownloadFileName(fileName);
            uiState.value.downloadFileName = finalName;
            const blob = new Blob([fullYaml.value], { type: 'text/yaml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = finalName;
            a.click();
            URL.revokeObjectURL(url);
        };

        const downloadYamlWithRename = () => {
            const currentName = normalizeDownloadFileName(uiState.value.downloadFileName || 'config.yaml');
            const input = window.prompt('请输入下载文件名（支持 .yaml / .yml）', currentName);
            if (input === null) return;
            downloadYaml(input);
        };

        return {
            normalizeImportedConfigData,
            triggerYamlImport,
            handleYamlImport,
            applyYamlImport,
            copyYaml,
            downloadYaml,
            downloadYamlWithRename
        };
    };
})(window);
