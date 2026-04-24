(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createYamlModule = function (ctx) {
        const { ref, config, uiState, providersList, ruleProvidersList, sanitizeProxyNodeForYaml, getRuleProviderUrl, getDefaultConfig } = ctx;
        const { parsePorts, parseHosts, parseYamlMapText, parseYamlSequenceText, parseYamlObjectText, parseMarkValue, getListenPort } = window.MihomoHelpers;

        const yamlSections = ref({ general: '', experimental: '', network: '', proxies: '', providers: '', ruleProviders: '', groups: '', subRules: '', rules: '' });
        const fullYaml = ref('');
        const getRuleProviderPathExt = (format) => format === 'text' ? 'list' : (format || 'mrs');
        const parseProxyNameOverride = (text) => parseYamlSequenceText(text, (item, index) => {
            if (!item || typeof item !== 'object' || Array.isArray(item)) {
                throw new Error(`override.proxy-name 第 ${index + 1} 项必须是映射对象`);
            }

            const pattern = String(item.pattern ?? '').trim();
            const target = String(item.target ?? '').trim();
            if (!pattern || !target) {
                throw new Error(`override.proxy-name 第 ${index + 1} 项必须同时包含 pattern 和 target`);
            }

            return { pattern, target };
        });
        const parseListenerUsersText = (text) => {
            const rawText = String(text || '').trim();
            if (!rawText) return undefined;

            let sequenceError = null;
            try {
                const parsedList = parseYamlSequenceText(rawText, (item) => item);
                if (parsedList && parsedList.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
                    return parsedList;
                }
            } catch (err) {
                sequenceError = err;
            }

            const parsedObject = parseYamlObjectText(rawText);
            if (parsedObject && typeof parsedObject === 'object' && !Array.isArray(parsedObject)) {
                return [parsedObject];
            }

            const detail = sequenceError && sequenceError.message ? `；列表解析错误：${sequenceError.message}` : '';
            throw new Error(`users 请输入 YAML 列表、JSON 数组，或单个 JSON/YAML 对象${detail}`);
        };
        const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);
        const pruneEmptyYamlValue = (value) => {
            if (value === undefined || value === null) return undefined;
            if (typeof value === 'string') return value.trim() === '' ? undefined : value;
            if (Array.isArray(value)) {
                const next = value
                    .map((item) => pruneEmptyYamlValue(item))
                    .filter((item) => item !== undefined);
                return next.length > 0 ? next : undefined;
            }
            if (isPlainObject(value)) {
                const next = {};
                Object.keys(value).forEach((key) => {
                    if (key.startsWith('_')) return;
                    const pruned = pruneEmptyYamlValue(value[key]);
                    if (pruned !== undefined) next[key] = pruned;
                });
                return Object.keys(next).length > 0 ? next : undefined;
            }
            return value;
        };
        const stripDefaultFalseFlags = (value, defaults) => {
            if (value === undefined || value === null) return value;
            if (value === false && defaults === false) return undefined;

            if (Array.isArray(value)) {
                const next = value
                    .map((item, index) => stripDefaultFalseFlags(item, Array.isArray(defaults) ? defaults[index] : undefined))
                    .filter((item) => item !== undefined);
                return next.length > 0 ? next : undefined;
            }

            if (isPlainObject(value)) {
                const next = {};
                Object.keys(value).forEach((key) => {
                    if (key.startsWith('_')) return;
                    const stripped = stripDefaultFalseFlags(value[key], defaults && defaults[key]);
                    if (stripped !== undefined) next[key] = stripped;
                });
                return Object.keys(next).length > 0 ? next : undefined;
            }

            return value;
        };
        const sanitizeListenerForYaml = (listener) => {
            const type = String(listener.type || '').trim();
            const nextListener = {
                name: String(listener.name || '').trim(),
                type,
                listen: String(listener.listen || '').trim(),
                port: listener.port
            };
            if (['mixed', 'socks', 'tproxy'].includes(type) && listener.udp !== undefined) nextListener.udp = listener.udp;
            if (listener.proxy) nextListener.proxy = String(listener.proxy).trim();
            if (listener.rule) nextListener.rule = String(listener.rule).trim();
            if (listener.token) nextListener.token = String(listener.token).trim();

            if (['mixed', 'http', 'socks'].includes(type)) {
                if (typeof listener._usersText === 'string' && listener._usersText.trim()) {
                    nextListener.users = parseListenerUsersText(listener._usersText);
                } else if (Array.isArray(listener.users) && listener.users.length > 0) {
                    nextListener.users = listener.users;
                }
                if (listener.certificate) nextListener.certificate = String(listener.certificate).trim();
                if (listener['private-key']) nextListener['private-key'] = String(listener['private-key']).trim();
                if (listener['client-auth-type']) nextListener['client-auth-type'] = String(listener['client-auth-type']).trim();
                if (listener['client-auth-cert']) nextListener['client-auth-cert'] = String(listener['client-auth-cert']).trim();
                if (listener['ech-key']) nextListener['ech-key'] = String(listener['ech-key']).trim();
                if (listener['ech-cert']) nextListener['ech-cert'] = String(listener['ech-cert']).trim();
            }
            return pruneEmptyYamlValue(nextListener);
        };
        const buildYaml = () => {
            try {
                const raw = JSON.parse(JSON.stringify(config.value));
                const defaultConfig = typeof getDefaultConfig === 'function' ? getDefaultConfig() : {};
                const parseText = (text) => text ? (text||'').split('\n').map(s => s.trim()).filter(Boolean) : [];
                const parseNumberishText = (text) => parseText(text).map((item) => (/^\d+$/.test(item) ? Number(item) : item));
                const opts = { indent: 2, lineWidth: -1, noRefs: true, sortKeys: false };

                let outGeneral = {};

                Object.assign(outGeneral, {
                    'mixed-port': raw['mixed-port'],
                    port: raw.port,
                    'socks-port': raw['socks-port'],
                    'redir-port': raw['redir-port'],
                    'tproxy-port': uiState.value.tproxyEnable ? (raw['tproxy-port'] || uiState.value.nftablesConfig.tproxyPort || 7894) : raw['tproxy-port'],
                    'allow-lan': raw['allow-lan'], mode: raw.mode, 'log-level': raw['log-level'], ipv6: raw.ipv6,
                    'external-controller': raw['external-controller']
                });

                ['mixed-port', 'port', 'socks-port', 'redir-port', 'tproxy-port'].forEach(k => {
                    if (!outGeneral[k] && outGeneral[k] !== 0) delete outGeneral[k];
                });

                if (raw['global-client-fingerprint']) outGeneral['global-client-fingerprint'] = raw['global-client-fingerprint'];
                if (raw['bind-address']) outGeneral['bind-address'] = raw['bind-address'];
                if (raw.secret) outGeneral.secret = raw.secret;
                if (raw['keep-alive-interval'] !== '' && raw['keep-alive-interval'] !== undefined) outGeneral['keep-alive-interval'] = raw['keep-alive-interval'];
                if (raw['keep-alive-idle'] !== '' && raw['keep-alive-idle'] !== undefined) outGeneral['keep-alive-idle'] = raw['keep-alive-idle'];
                if (raw['disable-keep-alive'] !== undefined) outGeneral['disable-keep-alive'] = raw['disable-keep-alive'];
                if (raw['external-ui']) outGeneral['external-ui'] = raw['external-ui'];
                if (raw['external-ui-name']) outGeneral['external-ui-name'] = raw['external-ui-name'];
                if (raw['external-ui-url']) outGeneral['external-ui-url'] = raw['external-ui-url'];
                if (raw['interface-name']) outGeneral['interface-name'] = raw['interface-name'];
                if (raw['geodata-mode'] !== undefined) outGeneral['geodata-mode'] = raw['geodata-mode'];
                if (raw['geodata-loader'] && raw['geodata-loader'] !== defaultConfig['geodata-loader']) {
                    outGeneral['geodata-loader'] = raw['geodata-loader'];
                }
                if (raw['global-ua']) outGeneral['global-ua'] = raw['global-ua'];
                if (raw['etag-support'] !== undefined && raw['etag-support'] !== defaultConfig['etag-support']) {
                    outGeneral['etag-support'] = raw['etag-support'];
                }
                if (raw['external-controller-unix']) outGeneral['external-controller-unix'] = raw['external-controller-unix'];
                if (raw['external-controller-pipe']) outGeneral['external-controller-pipe'] = raw['external-controller-pipe'];
                if (raw['external-controller-tls']) outGeneral['external-controller-tls'] = raw['external-controller-tls'];

                const lanAllowedIps = parseText(uiState.value.generalLanAllowedIps);
                if (lanAllowedIps.length > 0) outGeneral['lan-allowed-ips'] = lanAllowedIps;
                const lanDisallowedIps = parseText(uiState.value.generalLanDisallowedIps);
                if (lanDisallowedIps.length > 0) outGeneral['lan-disallowed-ips'] = lanDisallowedIps;
                const authentication = parseText(uiState.value.generalAuthentication);
                if (authentication.length > 0) outGeneral.authentication = authentication;
                const skipAuthPrefixes = parseText(uiState.value.generalSkipAuthPrefixes);
                if (skipAuthPrefixes.length > 0) outGeneral['skip-auth-prefixes'] = skipAuthPrefixes;
                const parsedCors = parseYamlMapText(uiState.value.externalControllerCorsText);
                if (parsedCors) outGeneral['external-controller-cors'] = parsedCors;
                const parsedTls = parseYamlMapText(uiState.value.tlsConfigText);
                if (parsedTls) outGeneral.tls = parsedTls;

                if (raw.geo) {
                    outGeneral['geo-auto-update'] = raw.geo['auto-update'];
                    outGeneral['geo-update-interval'] = raw.geo.interval;
                    outGeneral['geox-url'] = raw.geo.url;
                }

                if (raw['unified-delay'] !== undefined && raw['unified-delay'] !== defaultConfig['unified-delay']) {
                    outGeneral['unified-delay'] = raw['unified-delay'];
                }
                if (raw['tcp-concurrent'] !== undefined && raw['tcp-concurrent'] !== defaultConfig['tcp-concurrent']) {
                    outGeneral['tcp-concurrent'] = raw['tcp-concurrent'];
                }

                if (raw.profile && (raw.profile['store-selected'] || raw.profile['store-selected'] === false)) {
                    outGeneral.profile = raw.profile;
                }
                if (raw['find-process-mode'] !== 'always') outGeneral['find-process-mode'] = raw['find-process-mode'];

                let rMarkInt = parseMarkValue(uiState.value.nftablesConfig.routeMarkHex, 112);
                outGeneral['routing-mark'] = rMarkInt;

                let finalListeners = [];
                if (raw.listeners && Array.isArray(raw.listeners)) {
                    finalListeners = JSON.parse(JSON.stringify(raw.listeners));
                }

                let tpIndex = finalListeners.findIndex(l => l.type === 'tproxy');
                if (uiState.value.tproxyEnable) {
                    if (tpIndex > -1) {
                        finalListeners[tpIndex].port = uiState.value.nftablesConfig.tproxyPort || raw['tproxy-port'] || 7894;
                        finalListeners[tpIndex].listen = uiState.value.nftablesConfig.listen || '0.0.0.0';
                        finalListeners[tpIndex].udp = uiState.value.nftablesConfig.udp !== false;
                    } else {
                        finalListeners.push({
                            name: 'tproxy-in',
                            type: 'tproxy',
                            port: uiState.value.nftablesConfig.tproxyPort || raw['tproxy-port'] || 7894,
                            listen: uiState.value.nftablesConfig.listen || '0.0.0.0',
                            udp: uiState.value.nftablesConfig.udp !== false
                        });
                    }
                } else {
                    if (tpIndex > -1) finalListeners.splice(tpIndex, 1);
                }

                finalListeners = finalListeners
                    .map((listener) => sanitizeListenerForYaml(listener))
                    .filter(Boolean);

                if (finalListeners.length > 0) outGeneral.listeners = finalListeners;

                let outExperimental = {};
                if (raw.experimental && typeof raw.experimental === 'object' && !Array.isArray(raw.experimental)) {
                    Object.keys(raw.experimental).forEach((key) => {
                        const value = raw.experimental[key];
                        if (typeof value === 'boolean') {
                            if (value) outExperimental[key] = true;
                            return;
                        }
                        if (value !== undefined && value !== null && value !== '') outExperimental[key] = value;
                    });
                }
                if (Object.keys(outExperimental).length > 0) {
                    outExperimental = { experimental: outExperimental };
                }

                let outNetwork = {};
                if (raw.tun && raw.tun.enable) {
                    outNetwork.tun = {
                        enable: true,
                        stack: raw.tun.stack,
                        'auto-route': raw.tun['auto-route'],
                        'auto-redirect': raw.tun['auto-redirect'],
                        'auto-detect-interface': raw.tun['auto-detect-interface']
                    };
                    if (raw.tun.device && raw.tun.device.trim() !== '') outNetwork.tun.device = raw.tun.device.trim();
                    if (raw.tun.mtu) outNetwork.tun.mtu = raw.tun.mtu;
                    if (raw.tun.gso !== undefined) outNetwork.tun.gso = raw.tun.gso;
                    if (raw.tun.gso && raw.tun['gso-max-size']) outNetwork.tun['gso-max-size'] = raw.tun['gso-max-size'];
                    if (raw.tun['strict-route'] !== undefined) outNetwork.tun['strict-route'] = raw.tun['strict-route'];
                    if (raw.tun['udp-timeout'] !== undefined && raw.tun['udp-timeout'] !== '') outNetwork.tun['udp-timeout'] = raw.tun['udp-timeout'];
                    if (raw.tun['iproute2-table-index'] !== undefined && raw.tun['iproute2-table-index'] !== '') outNetwork.tun['iproute2-table-index'] = raw.tun['iproute2-table-index'];
                    if (raw.tun['iproute2-rule-index'] !== undefined && raw.tun['iproute2-rule-index'] !== '') outNetwork.tun['iproute2-rule-index'] = raw.tun['iproute2-rule-index'];
                    if (raw.tun['endpoint-independent-nat'] !== undefined) outNetwork.tun['endpoint-independent-nat'] = raw.tun['endpoint-independent-nat'];

                    const hijack = uiState.value.tunDnsHijackEnabled
                        ? (uiState.value.tunDnsHijack||'').split('\n').map(s=>s.trim()).filter(Boolean)
                        : [];
                    if (uiState.value.tunDnsHijackEnabled && hijack.length > 0) outNetwork.tun['dns-hijack'] = hijack;

                    const routeAddressSet = parseText(uiState.value.tunRouteAddressSet);
                    const routeExcludeAddressSet = parseText(uiState.value.tunRouteExcludeAddressSet);
                    const routeAddress = parseText(uiState.value.tunRouteAddress);
                    const routeExcludeAddress = parseText(uiState.value.tunRouteExcludeAddress);
                    const includeInterface = parseText(uiState.value.tunIncludeInterface);
                    const excludeInterface = parseText(uiState.value.tunExcludeInterface);
                    const includeUid = parseNumberishText(uiState.value.tunIncludeUid);
                    const includeUidRange = parseText(uiState.value.tunIncludeUidRange);
                    const excludeUid = parseNumberishText(uiState.value.tunExcludeUid);
                    const excludeUidRange = parseText(uiState.value.tunExcludeUidRange);
                    const includeAndroidUser = parseNumberishText(uiState.value.tunIncludeAndroidUser);
                    const includePackage = parseText(uiState.value.tunIncludePackage);
                    const excludePackage = parseText(uiState.value.tunExcludePackage);

                    if (routeAddressSet.length > 0) outNetwork.tun['route-address-set'] = routeAddressSet;
                    if (routeExcludeAddressSet.length > 0) outNetwork.tun['route-exclude-address-set'] = routeExcludeAddressSet;
                    if (routeAddress.length > 0) outNetwork.tun['route-address'] = routeAddress;
                    if (routeExcludeAddress.length > 0) outNetwork.tun['route-exclude-address'] = routeExcludeAddress;
                    if (includeInterface.length > 0) outNetwork.tun['include-interface'] = includeInterface;
                    if (excludeInterface.length > 0) outNetwork.tun['exclude-interface'] = excludeInterface;
                    if (includeUid.length > 0) outNetwork.tun['include-uid'] = includeUid;
                    if (includeUidRange.length > 0) outNetwork.tun['include-uid-range'] = includeUidRange;
                    if (excludeUid.length > 0) outNetwork.tun['exclude-uid'] = excludeUid;
                    if (excludeUidRange.length > 0) outNetwork.tun['exclude-uid-range'] = excludeUidRange;
                    if (includeAndroidUser.length > 0) outNetwork.tun['include-android-user'] = includeAndroidUser;
                    if (includePackage.length > 0) outNetwork.tun['include-package'] = includePackage;
                    if (excludePackage.length > 0) outNetwork.tun['exclude-package'] = excludePackage;
                }

                if (raw.sniffer && raw.sniffer.enable) {
                    outNetwork.sniffer = {
                        enable: true, 'force-dns-mapping': raw.sniffer['force-dns-mapping'], 'parse-pure-ip': raw.sniffer['parse-pure-ip'], 'override-destination': raw.sniffer['override-destination']
                    };

                    let sHTTP = parsePorts(uiState.value.snifferSniff?.HTTP);
                    let sTLS = parsePorts(uiState.value.snifferSniff?.TLS);
                    let sQUIC = parsePorts(uiState.value.snifferSniff?.QUIC);
                    if (sHTTP.length > 0 || sTLS.length > 0 || sQUIC.length > 0) {
                        outNetwork.sniffer.sniff = {};
                        if (sHTTP.length > 0) {
                            outNetwork.sniffer.sniff.HTTP = { ports: sHTTP };
                            if (uiState.value.snifferSniffOverrideDestination?.HTTP) outNetwork.sniffer.sniff.HTTP['override-destination'] = true;
                        }
                        if (sTLS.length > 0) {
                            outNetwork.sniffer.sniff.TLS = { ports: sTLS };
                            if (uiState.value.snifferSniffOverrideDestination?.TLS) outNetwork.sniffer.sniff.TLS['override-destination'] = true;
                        }
                        if (sQUIC.length > 0) {
                            outNetwork.sniffer.sniff.QUIC = { ports: sQUIC };
                            if (uiState.value.snifferSniffOverrideDestination?.QUIC) outNetwork.sniffer.sniff.QUIC['override-destination'] = true;
                        }
                    }
                    const skips = parseText(uiState.value.snifferSkipDomain);
                    if(skips.length > 0) outNetwork.sniffer['skip-domain'] = skips;
                    const forces = parseText(uiState.value.snifferForceDomain);
                    if(forces.length > 0) outNetwork.sniffer['force-domain'] = forces;
                    const whitelists = parseText(uiState.value.snifferPortWhitelist);
                    if(whitelists.length > 0) outNetwork.sniffer['port-whitelist'] = whitelists.map(p => isNaN(p) ? p : Number(p));
                    const skipSrcAddress = parseText(uiState.value.snifferSkipSrcAddress);
                    if (skipSrcAddress.length > 0) outNetwork.sniffer['skip-src-address'] = skipSrcAddress;
                    const skipDstAddress = parseText(uiState.value.snifferSkipDstAddress);
                    if (skipDstAddress.length > 0) outNetwork.sniffer['skip-dst-address'] = skipDstAddress;
                }

                if (raw.dns && raw.dns.enable) {
                    outNetwork.dns = { ...raw.dns };
                    const normalizedDnsListen = getListenPort(raw.dns.listen, 53);
                    outNetwork.dns.listen = `:${normalizedDnsListen}`;
                    if (raw.dns['cache-algorithm'] === defaultConfig.dns?.['cache-algorithm']) {
                        delete outNetwork.dns['cache-algorithm'];
                    }
                    if (outNetwork.dns['enhanced-mode'] === 'fake-ip') {
                        outNetwork.dns['fake-ip-filter-mode'] = raw.dns['fake-ip-filter-mode'];
                        if (!String(raw.dns['fake-ip-range6'] || '').trim()) delete outNetwork.dns['fake-ip-range6'];
                        const fakeIpTtl = Number(raw.dns['fake-ip-ttl']);
                        if (!Number.isFinite(fakeIpTtl) || fakeIpTtl <= 0) delete outNetwork.dns['fake-ip-ttl'];
                        const filters = parseText(uiState.value.fakeIpFilter);
                        if (filters.length > 0) outNetwork.dns['fake-ip-filter'] = filters;
                    } else {
                        delete outNetwork.dns['fake-ip-range'];
                        delete outNetwork.dns['fake-ip-range6'];
                        delete outNetwork.dns['fake-ip-filter-mode'];
                        delete outNetwork.dns['fake-ip-ttl'];
                    }

                    const nameserverPolicyText = String(uiState.value.dnsNameserverPolicy || '').trim();
                    const directNameservers = parseText(uiState.value.dnsDirectNameservers);

                    outNetwork.dns['default-nameserver'] = parseText(uiState.value.dnsDefaultNameservers);
                    outNetwork.dns.nameserver = parseText(uiState.value.dnsNameservers);
                    if (uiState.value.enableDnsFallback) {
                        outNetwork.dns.fallback = parseText(uiState.value.dnsFallback);
                    } else {
                        delete outNetwork.dns.fallback;
                    }
                    outNetwork.dns['proxy-server-nameserver'] = parseText(uiState.value.dnsProxyServerNameservers);
                    outNetwork.dns['direct-nameserver'] = directNameservers;

                    if (nameserverPolicyText) {
                        const parsedPolicy = parseYamlMapText(nameserverPolicyText);
                        if (parsedPolicy) outNetwork.dns['nameserver-policy'] = parsedPolicy;
                    }

                    if (!nameserverPolicyText) delete outNetwork.dns['nameserver-policy'];
                    if (!nameserverPolicyText || directNameservers.length === 0) {
                        delete outNetwork.dns['direct-nameserver-follow-policy'];
                    }

                    if (uiState.value.enableProxyServerNameserverPolicy) {
                        const parsedProxyPolicy = parseYamlMapText(uiState.value.dnsProxyServerNameserverPolicy);
                        if (parsedProxyPolicy) outNetwork.dns['proxy-server-nameserver-policy'] = parsedProxyPolicy;
                    } else {
                        delete outNetwork.dns['proxy-server-nameserver-policy'];
                    }

                    if (uiState.value.enableDnsFallback && outNetwork.dns.fallback && outNetwork.dns.fallback.length > 0) {
                        if (!outNetwork.dns['fallback-filter']) outNetwork.dns['fallback-filter'] = {};

                        outNetwork.dns['fallback-filter'].geoip = config.value.dns['fallback-filter']?.geoip !== false;
                        if (outNetwork.dns['fallback-filter'].geoip) {
                            outNetwork.dns['fallback-filter']['geoip-code'] = config.value.dns['fallback-filter']['geoip-code'] || 'CN';
                        } else {
                            delete outNetwork.dns['fallback-filter']['geoip-code'];
                        }

                        const geosite = parseText(uiState.value.fallbackFilterGeosite);
                        if (uiState.value.fallbackFilterGeositeEnable && geosite.length > 0) outNetwork.dns['fallback-filter'].geosite = geosite;

                        const ipcidr = parseText(uiState.value.fallbackFilterIpcidr);
                        const domain = parseText(uiState.value.fallbackFilterDomain);
                        if (ipcidr.length > 0) outNetwork.dns['fallback-filter'].ipcidr = ipcidr;
                        if (domain.length > 0) outNetwork.dns['fallback-filter'].domain = domain;
                    } else {
                        delete outNetwork.dns.fallback;
                        delete outNetwork.dns['fallback-filter'];
                    }

                    ['default-nameserver', 'nameserver', 'fallback', 'proxy-server-nameserver', 'direct-nameserver'].forEach(k => { if (outNetwork.dns[k] && outNetwork.dns[k].length === 0) delete outNetwork.dns[k]; });
                }

                if (raw.dns && raw.dns['use-hosts']) {
                    const parsedHosts = parseHosts(uiState.value.hosts);
                    if (parsedHosts) outNetwork.hosts = parsedHosts;
                }

                const providerNames = (providersList.value || []).map(p => p.name).filter(Boolean);
                const groupNames = (raw['proxy-groups'] || []).map(g => g.name).filter(Boolean);
                const proxyNames = (raw.proxies || []).map(p => p.name).filter(Boolean);
                const validStaticMembers = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', ...groupNames, ...proxyNames]);
                const defaultRuleTarget = groupNames[0] || 'DIRECT';
                const normalizeRuleTarget = (target) => validStaticMembers.has(target) ? target : defaultRuleTarget;
                const getRuleTarget = (rule) => rule && rule.type === 'SUB-RULE'
                    ? (rule.target || '')
                    : normalizeRuleTarget(rule && rule.target);
                const normalizeDialerProxy = (value) => value && validStaticMembers.has(value) ? value : '';
                let outProxies = {};
                if (raw.proxies && raw.proxies.length > 0) {
                    outProxies.proxies = raw.proxies.map(px => sanitizeProxyNodeForYaml(px)).filter(Boolean);
                }

                let outProviders = {};
                if (providersList.value && providersList.value.length > 0) {
                    outProviders['proxy-providers'] = {};
                    const resolveEffectiveProvider = (provider) => {
                        if (!provider || provider._chainMode !== 'provider' || !provider._sourceProviderName) return provider;
                        const source = (providersList.value || []).find((item) => item && item.name === provider._sourceProviderName && !item._chainMode);
                        if (!source || !['http', 'file'].includes(source.type)) return null;
                        return {
                            ...source,
                            ...provider,
                            type: source.type,
                            url: source.url,
                            path: source.path,
                            interval: source.interval,
                            proxy: source.proxy,
                            sizeLimit: source.sizeLimit,
                            headers: source.headers,
                            lazy: source.lazy,
                            healthCheckEnable: source.healthCheckEnable,
                            healthUrl: source.healthUrl,
                            healthCheckInterval: source.healthCheckInterval,
                            healthCheckLazy: source.healthCheckLazy,
                            healthCheckTimeout: source.healthCheckTimeout,
                            healthExpectedStatus: source.healthExpectedStatus,
                            _chainMode: provider._chainMode,
                            _sourceProviderName: provider._sourceProviderName,
                            name: provider.name,
                            filter: provider.filter || '',
                            excludeFilter: provider.excludeFilter || '',
                            excludeType: provider.excludeType || '',
                            overrideDialerProxy: provider.overrideDialerProxy || '',
                            overrideAdditionalPrefix: provider.overrideAdditionalPrefix || '',
                            overrideAdditionalSuffix: provider.overrideAdditionalSuffix || '',
                            overrideProxyName: provider.overrideProxyName || ''
                        };
                    };
                    providersList.value.forEach(p => {
                        const effectiveProvider = resolveEffectiveProvider(p);
                        if (effectiveProvider && effectiveProvider.name) {
                            const providerType = effectiveProvider.type || 'http';
                            let prov = { type: providerType };

                            if (providerType === 'http') {
                                const url = String(effectiveProvider.url || '').trim();
                                if (!url) return;
                                prov.url = url;
                            }

                            if (providerType === 'http' || providerType === 'file') {
                                const providerPath = String(effectiveProvider.path || '').trim() || `./providers/${effectiveProvider.name}.yaml`;
                                const providerInterval = Number(effectiveProvider.interval);
                                const normalizedProviderProxy = normalizeDialerProxy(effectiveProvider.proxy || effectiveProvider.downloadProxy);
                                const parsedHeaders = parseYamlMapText(effectiveProvider.headers);
                                const sizeLimitText = String(effectiveProvider.sizeLimit ?? '').trim();
                                const sizeLimit = Number(sizeLimitText);
                                const healthCheck = {
                                    enable: effectiveProvider.healthCheckEnable !== false,
                                    interval: Number(effectiveProvider.healthCheckInterval) > 0 ? Number(effectiveProvider.healthCheckInterval) : 600,
                                    url: effectiveProvider.healthUrl || 'https://www.gstatic.com/generate_204',
                                    lazy: effectiveProvider.healthCheckLazy !== false,
                                    timeout: Number(effectiveProvider.healthCheckTimeout) > 0 ? Number(effectiveProvider.healthCheckTimeout) : 5000
                                };
                                const healthExpectedStatus = String(effectiveProvider.healthExpectedStatus ?? '').trim();

                                prov.path = providerPath;
                                if (providerInterval > 0) prov.interval = providerInterval;
                                else if (providerType === 'http') prov.interval = 3600;
                                if (effectiveProvider.lazy !== undefined) prov.lazy = effectiveProvider.lazy;
                                if (normalizedProviderProxy) prov.proxy = normalizedProviderProxy;
                                if (sizeLimitText !== '' && Number.isFinite(sizeLimit) && sizeLimit >= 0) {
                                    prov['size-limit'] = sizeLimit;
                                }
                                if (parsedHeaders) prov.header = parsedHeaders;
                                if (healthExpectedStatus) healthCheck['expected-status'] = healthExpectedStatus;
                                prov['health-check'] = healthCheck;
                            } else if (providerType === 'inline') {
                                let payloadNodes = [];
                                if (effectiveProvider.inlineProxies && effectiveProvider.inlineProxies.length > 0) {
                                    payloadNodes = effectiveProvider.inlineProxies
                                        .map((pxName) => sanitizeProxyNodeForYaml((raw.proxies || []).find((x) => x.name === pxName)))
                                        .filter(Boolean);
                                }
                                prov.payload = payloadNodes;
                            }

                            const providerOverride = {};
                            const normalizedOverrideDialerProxy = normalizeDialerProxy(effectiveProvider.overrideDialerProxy);
                            const overrideAdditionalPrefix = String(effectiveProvider.overrideAdditionalPrefix ?? '').trim();
                            const overrideAdditionalSuffix = String(effectiveProvider.overrideAdditionalSuffix ?? '').trim();
                            const overrideProxyName = parseProxyNameOverride(effectiveProvider.overrideProxyName);
                            if (normalizedOverrideDialerProxy) providerOverride['dialer-proxy'] = normalizedOverrideDialerProxy;
                            if (overrideAdditionalPrefix) providerOverride['additional-prefix'] = overrideAdditionalPrefix;
                            if (overrideAdditionalSuffix) providerOverride['additional-suffix'] = overrideAdditionalSuffix;
                            if (overrideProxyName) providerOverride['proxy-name'] = overrideProxyName;
                            if (Object.keys(providerOverride).length > 0) prov.override = providerOverride;

                            if (effectiveProvider.filter) prov.filter = effectiveProvider.filter;
                            if (effectiveProvider.excludeFilter) prov['exclude-filter'] = effectiveProvider.excludeFilter;
                            if (effectiveProvider.excludeType) prov['exclude-type'] = effectiveProvider.excludeType;

                            if (providerType === 'file' && !prov.path) {
                                prov.path = `./providers/${effectiveProvider.name}.yaml`;
                            }
                            outProviders['proxy-providers'][effectiveProvider.name] = prov;
                        }
                    });
                }

                let outRuleProviders = {};
                if (ruleProvidersList.value && ruleProvidersList.value.length > 0) {
                    outRuleProviders['rule-providers'] = {};
                    ruleProvidersList.value.forEach(rp => {
                        if (!rp.name) return;
                        let rProv = { type: rp.type || 'http', behavior: rp.behavior };
                        if (rp.type !== 'inline') rProv.format = rp.format;
                        if (rp.type === 'http') {
                            const url = rp.autoUrl ? getRuleProviderUrl(rp) : rp.customUrl;
                            if (!url) return;
                            const ruleProviderPath = String(rp.path || '').trim() || `./rules/${rp.name}.${getRuleProviderPathExt(rp.format)}`;
                            const normalizedRuleProviderProxy = normalizeDialerProxy(rp.proxy);
                            const parsedRuleProviderHeaders = parseYamlMapText(rp.headers);
                            const sizeLimitText = String(rp.sizeLimit ?? '').trim();
                            const sizeLimit = Number(sizeLimitText);

                            rProv.path = ruleProviderPath;
                            rProv.url = url;
                            rProv.interval = rp.interval || 86400;
                            if (normalizedRuleProviderProxy) rProv.proxy = normalizedRuleProviderProxy;
                            if (sizeLimitText !== '' && Number.isFinite(sizeLimit) && sizeLimit >= 0) {
                                rProv['size-limit'] = sizeLimit;
                            }
                            if (parsedRuleProviderHeaders) rProv.header = parsedRuleProviderHeaders;
                        } else if (rp.type === 'file') {
                            rProv.path = rp.path || `./rules/${rp.name}.${getRuleProviderPathExt(rp.format)}`;
                        } else if (rp.type === 'inline') {
                            rProv.payload = parseText(rp.payload);
                        }
                        outRuleProviders['rule-providers'][rp.name] = rProv;
                    });
                }

                let outGroups = {};
                if (raw['proxy-groups'] && raw['proxy-groups'].length > 0) {
                    outGroups['proxy-groups'] = raw['proxy-groups'].map(g => {
                        let cg = { name: g.name, type: g.type };
                        if (g['include-all-proxies']) cg['include-all-proxies'] = true;
                        if (g['include-all-providers']) cg['include-all-providers'] = true;
                        if (g.hidden) cg.hidden = true;
                        if (g.icon) cg.icon = g.icon;

                        if(g.type === 'load-balance') cg.strategy = g.strategy || 'consistent-hashing';

                        if(g.type !== 'relay') {
                            if(!cg['include-all-proxies']) {
                                if(g.proxies && g.proxies.length>0) cg.proxies = g.proxies.filter(name => validStaticMembers.has(name));
                            }
                            if(!cg['include-all-providers'] && g.use && g.use.length>0) cg.use = g.use.filter(name => providerNames.includes(name));
                            if(g.filter) cg.filter = g.filter;
                            if(g['exclude-filter']) cg['exclude-filter'] = g['exclude-filter'];
                            if(g['exclude-type']) cg['exclude-type'] = g['exclude-type'];
                        } else {
                            if(g.proxies && g.proxies.length>0) cg.proxies = g.proxies;
                        }

                        if(g.type === 'url-test' || g.type === 'fallback' || g.type === 'load-balance') {
                            cg.url = g.url || 'https://www.gstatic.com/generate_204';
                            cg.interval = g.interval || 300;
                            if(g['max-failed-times'] !== undefined && g['max-failed-times'] !== '') cg['max-failed-times'] = g['max-failed-times'];
                            if(g['expected-status']) cg['expected-status'] = g['expected-status'];
                        }
                        if(g.type === 'url-test' || g.type === 'fallback') {
                            if (g.timeout > 0) cg.timeout = g.timeout;
                        }
                        if(g.type === 'url-test') { cg.tolerance = g.tolerance; cg.lazy = g.lazy; }
                        if(g['disable-udp']) cg['disable-udp'] = true;
                        if(g['interface-name']) cg['interface-name'] = g['interface-name'];
                        if(g['routing-mark'] !== undefined && g['routing-mark'] !== null && String(g['routing-mark']).trim() !== '') cg['routing-mark'] = /^\d+$/.test(String(g['routing-mark']).trim()) ? Number(g['routing-mark']) : g['routing-mark'];

                        if (cg.type === 'relay') {
                            delete cg.url; delete cg.interval; delete cg.timeout; delete cg.tolerance; delete cg.lazy;
                        }
                        return cg;
                    });
                } else { outGroups['proxy-groups'] = [{ name: 'Proxy', type: 'select', proxies: ['DIRECT'] }]; }

                let outSubRules = {};
                const parsedSubRules = parseYamlObjectText(uiState.value.subRulesYaml);
                if (parsedSubRules) outSubRules['sub-rules'] = parsedSubRules;

                let outRules = { rules: [] };
                if (uiState.value.rules) {
                    outRules.rules = uiState.value.rules.map(r => {
                        const ipTypes = ['GEOIP', 'SRC-GEOIP', 'IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'IP-SUFFIX', 'IP-ASN', 'SRC-IP-SUFFIX', 'SRC-IP-ASN'];
                        if (r.logic) {
                            const parts = (r.conditions||[]).map(c => {
                                let innerVal = c.type === 'DOMAIN-REGEX' && c.value && c.value.includes(',') ? `"${c.value}"` : c.value;
                                let inner = `${c.type},${innerVal}`;
                                if (c.noResolve && ipTypes.includes(c.type)) inner += ',no-resolve';
                                if (c.src) inner += `,src,${c.src}`;
                                return c.not ? `NOT,((${inner}))` : `(${inner})`;
                            });
                            const body = `${r.logic},(${parts.join(',')})`;
                            const wrapped = r.not ? `NOT,((${body}))` : body;
                            return `${wrapped},${normalizeRuleTarget(r.target)}`;
                        }
                        if (r.type === 'MATCH') return `MATCH,${normalizeRuleTarget(r.target)}`;
                        let outerVal = r.type === 'DOMAIN-REGEX' && r.value && r.value.includes(',') ? `"${r.value}"` : r.value;
                        let inner = `${r.type},${outerVal}`;
                        if (r.not) {
                            if (r.noResolve && ipTypes.includes(r.type)) inner += ',no-resolve';
                            if (r.src) inner += `,src,${r.src}`;
                            return `NOT,((${inner})),${getRuleTarget(r)}`;
                        } else {
                            let ruleStr = `${inner},${getRuleTarget(r)}`;
                            if (r.noResolve && ipTypes.includes(r.type)) ruleStr += ',no-resolve';
                            if (r.src) ruleStr += `,src,${r.src}`;
                            return ruleStr;
                        }
                    });
                }
                if (!outRules.rules.some(r => r.startsWith('MATCH'))) outRules.rules.push(`MATCH,${defaultRuleTarget}`);

                const dump = (obj, defaults) => {
                    const stripped = stripDefaultFalseFlags(obj, defaults);
                    const pruned = pruneEmptyYamlValue(stripped);
                    return pruned && Object.keys(pruned).length > 0 ? jsyaml.dump(pruned, opts) : '';
                };

                yamlSections.value = {
                    general: dump(outGeneral, defaultConfig),
                    experimental: dump(outExperimental, { experimental: defaultConfig.experimental || {} }),
                    network: dump(outNetwork, {
                        tun: defaultConfig.tun || {},
                        sniffer: defaultConfig.sniffer || {},
                        dns: defaultConfig.dns || {}
                    }),
                    proxies: dump(outProxies),
                    providers: dump(outProviders),
                    ruleProviders: dump(outRuleProviders),
                    groups: dump(outGroups),
                    subRules: dump(outSubRules),
                    rules: dump(outRules)
                };

                fullYaml.value = [yamlSections.value.general, yamlSections.value.experimental, yamlSections.value.network, yamlSections.value.proxies, yamlSections.value.providers, yamlSections.value.ruleProviders, yamlSections.value.groups, yamlSections.value.subRules, yamlSections.value.rules].filter(Boolean).join('');
            } catch (err) {
                console.error("YAML 构建遭遇异常:", err);
                throw err;
            }
        };

        return {
            yamlSections,
            fullYaml,
            buildYaml
        };
    };
})(window);
