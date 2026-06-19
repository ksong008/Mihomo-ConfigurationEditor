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
            runtimeValidationErrors,
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
        const {
            normalizeListenAddress,
            parseYamlMapText,
            parseYamlSequenceText,
            parseYamlObjectText,
            formatYamlSequenceText,
            formatYamlObjectText,
            normalizeTunnelListenerNetwork
        } = window.MihomoHelpers;

        const importModel = window.MihomoCore && window.MihomoCore.ImportModel;
        if (!importModel) {
            throw new Error('ImportModel 未加载，请确认先引入 ./core/import-model.js');
        }
        const {
            isPlainObject,
            safeJsonClone,
            ensureArray,
            normalizeImportedConfigData,
            listToMultilineText,
            formatProviderOverrideBooleanValue
        } = importModel.createImportModel({
            parseYamlMapText,
            parseYamlSequenceText,
            parseYamlObjectText,
            formatYamlSequenceText,
            formatYamlObjectText,
            normalizeTunnelListenerNetwork
        });

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
            config.value['geosite-matcher'] = data['geosite-matcher'] !== undefined ? data['geosite-matcher'] : getDefaultConfig()['geosite-matcher'];
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
            config.value['bind-address'] = data['bind-address'] !== undefined ? data['bind-address'] : getDefaultConfig()['bind-address'];
            if (data.mode !== undefined) config.value.mode = data.mode;
            if (data['log-level'] !== undefined) config.value['log-level'] = data['log-level'];
            if (data.ipv6 !== undefined) config.value.ipv6 = data.ipv6;
            config.value['keep-alive-interval'] = data['keep-alive-interval'] !== undefined ? data['keep-alive-interval'] : getDefaultConfig()['keep-alive-interval'];
            config.value['keep-alive-idle'] = data['keep-alive-idle'] !== undefined ? data['keep-alive-idle'] : getDefaultConfig()['keep-alive-idle'];
            config.value['disable-keep-alive'] = data['disable-keep-alive'] !== undefined ? data['disable-keep-alive'] : getDefaultConfig()['disable-keep-alive'];
            config.value['inbound-tfo'] = data['inbound-tfo'] !== undefined ? data['inbound-tfo'] : getDefaultConfig()['inbound-tfo'];
            config.value['inbound-mptcp'] = data['inbound-mptcp'] !== undefined ? data['inbound-mptcp'] : getDefaultConfig()['inbound-mptcp'];
            if (data['find-process-mode'] !== undefined) config.value['find-process-mode'] = data['find-process-mode'];
            if (data.profile) config.value.profile = { ...config.value.profile, ...data.profile };
            if (data['external-controller'] !== undefined) config.value['external-controller'] = data['external-controller'];
            config.value['external-controller-unix'] = data['external-controller-unix'] !== undefined ? data['external-controller-unix'] : getDefaultConfig()['external-controller-unix'];
            config.value['external-controller-pipe'] = data['external-controller-pipe'] !== undefined ? data['external-controller-pipe'] : getDefaultConfig()['external-controller-pipe'];
            config.value['external-controller-tls'] = data['external-controller-tls'] !== undefined ? data['external-controller-tls'] : getDefaultConfig()['external-controller-tls'];
            config.value['external-doh-server'] = data['external-doh-server'] !== undefined ? data['external-doh-server'] : getDefaultConfig()['external-doh-server'];
            if (data.secret !== undefined) config.value.secret = data.secret;
            if (data['external-ui'] !== undefined) config.value['external-ui'] = data['external-ui'];
            config.value['external-ui-name'] = data['external-ui-name'] !== undefined ? data['external-ui-name'] : getDefaultConfig()['external-ui-name'];
            config.value['external-ui-url'] = data['external-ui-url'] !== undefined ? data['external-ui-url'] : getDefaultConfig()['external-ui-url'];
            config.value['geodata-loader'] = data['geodata-loader'] !== undefined ? data['geodata-loader'] : getDefaultConfig()['geodata-loader'];
            config.value['global-ua'] = data['global-ua'] !== undefined ? data['global-ua'] : getDefaultConfig()['global-ua'];
            config.value['etag-support'] = data['etag-support'] !== undefined ? data['etag-support'] : getDefaultConfig()['etag-support'];
            config.value['external-controller-cors'] = data['external-controller-cors'] && typeof data['external-controller-cors'] === 'object' ? { ...data['external-controller-cors'] } : {};
            config.value.tls = data.tls && typeof data.tls === 'object' ? { ...data.tls } : {};
            config.value.experimental = data.experimental && typeof data.experimental === 'object' ? { ...config.value.experimental, ...data.experimental } : { ...getDefaultConfig().experimental };

            uiState.value.generalLanAllowedIps = listToMultilineText(data['lan-allowed-ips']);
            uiState.value.generalLanDisallowedIps = listToMultilineText(data['lan-disallowed-ips']);
            uiState.value.generalAuthentication = listToMultilineText(data.authentication);
            uiState.value.generalSkipAuthPrefixes = listToMultilineText(data['skip-auth-prefixes']);
            uiState.value.externalControllerCorsText = formatYamlMapText(data['external-controller-cors']);
            uiState.value.tlsConfigText = formatYamlMapText(data.tls);
            uiState.value.subRulesYaml = formatYamlObjectText(data['sub-rules']);

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

                uiState.value.tunRouteAddressSet = listToMultilineText(data.tun['route-address-set']);
                uiState.value.tunRouteExcludeAddressSet = listToMultilineText(data.tun['route-exclude-address-set']);
                uiState.value.tunRouteAddress = listToMultilineText(data.tun['route-address']);
                uiState.value.tunRouteExcludeAddress = listToMultilineText(data.tun['route-exclude-address']);
                uiState.value.tunIncludeInterface = listToMultilineText(data.tun['include-interface']);
                uiState.value.tunExcludeInterface = listToMultilineText(data.tun['exclude-interface']);
                uiState.value.tunIncludeUid = listToMultilineText(data.tun['include-uid']);
                uiState.value.tunIncludeUidRange = listToMultilineText(data.tun['include-uid-range']);
                uiState.value.tunExcludeUid = listToMultilineText(data.tun['exclude-uid']);
                uiState.value.tunExcludeUidRange = listToMultilineText(data.tun['exclude-uid-range']);
                uiState.value.tunIncludeAndroidUser = listToMultilineText(data.tun['include-android-user']);
                uiState.value.tunIncludePackage = listToMultilineText(data.tun['include-package']);
                uiState.value.tunExcludePackage = listToMultilineText(data.tun['exclude-package']);
            } else {
                config.value.tun.enable = false;
                uiState.value.tunDnsHijackEnabled = false;
                uiState.value.tunRouteAddressSet = '';
                uiState.value.tunRouteExcludeAddressSet = '';
                uiState.value.tunRouteAddress = '';
                uiState.value.tunRouteExcludeAddress = '';
                uiState.value.tunIncludeInterface = '';
                uiState.value.tunExcludeInterface = '';
                uiState.value.tunIncludeUid = '';
                uiState.value.tunIncludeUidRange = '';
                uiState.value.tunExcludeUid = '';
                uiState.value.tunExcludeUidRange = '';
                uiState.value.tunIncludeAndroidUser = '';
                uiState.value.tunIncludePackage = '';
                uiState.value.tunExcludePackage = '';
            }

            if (data.sniffer) {
                config.value.sniffer.enable = true;
                if (data.sniffer['force-dns-mapping'] !== undefined) config.value.sniffer['force-dns-mapping'] = data.sniffer['force-dns-mapping'];
                if (data.sniffer['parse-pure-ip'] !== undefined) config.value.sniffer['parse-pure-ip'] = data.sniffer['parse-pure-ip'];
                if (data.sniffer['override-destination'] !== undefined) config.value.sniffer['override-destination'] = data.sniffer['override-destination'];

                uiState.value.snifferSniff = { HTTP: '', TLS: '', QUIC: '' };
                uiState.value.snifferSniffOverrideDestination = { HTTP: false, TLS: false, QUIC: false };
                if (data.sniffer.sniff) {
                    if (data.sniffer.sniff.HTTP && data.sniffer.sniff.HTTP.ports) uiState.value.snifferSniff.HTTP = data.sniffer.sniff.HTTP.ports.join(', ');
                    if (data.sniffer.sniff.TLS && data.sniffer.sniff.TLS.ports) uiState.value.snifferSniff.TLS = data.sniffer.sniff.TLS.ports.join(', ');
                    if (data.sniffer.sniff.QUIC && data.sniffer.sniff.QUIC.ports) uiState.value.snifferSniff.QUIC = data.sniffer.sniff.QUIC.ports.join(', ');
                }

                uiState.value.snifferSkipDomain = listToMultilineText(data.sniffer['skip-domain']);
                uiState.value.snifferForceDomain = listToMultilineText(data.sniffer['force-domain']);
                uiState.value.snifferPortWhitelist = listToMultilineText(data.sniffer['port-whitelist']);
                uiState.value.snifferSkipSrcAddress = listToMultilineText(data.sniffer['skip-src-address']);
                uiState.value.snifferSkipDstAddress = listToMultilineText(data.sniffer['skip-dst-address']);
                uiState.value.snifferSniffOverrideDestination = {
                    HTTP: !!data.sniffer.sniff?.HTTP?.['override-destination'],
                    TLS: !!data.sniffer.sniff?.TLS?.['override-destination'],
                    QUIC: !!data.sniffer.sniff?.QUIC?.['override-destination']
                };
            } else {
                config.value.sniffer.enable = false;
                uiState.value.snifferSniff = { HTTP: '', TLS: '', QUIC: '' };
                uiState.value.snifferSkipSrcAddress = '';
                uiState.value.snifferSkipDstAddress = '';
                uiState.value.snifferSniffOverrideDestination = { HTTP: false, TLS: false, QUIC: false };
            }

            if (data.dns) {
                config.value.dns.enable = true;
                ['listen', 'ipv6', 'ipv6-timeout', 'enhanced-mode', 'fake-ip-range', 'fake-ip-range6', 'fake-ip-filter-mode', 'fake-ip-ttl', 'cache-algorithm', 'cache-max-size', 'prefer-h3', 'respect-rules', 'use-hosts', 'use-system-hosts', 'direct-nameserver-follow-policy'].forEach(k => {
                    if (data.dns[k] !== undefined) config.value.dns[k] = data.dns[k];
                });
                config.value.dns.listen = normalizeListenAddress(config.value.dns.listen, ':53');

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

                if (data.dns['proxy-server-nameserver-policy']) {
                    uiState.value.enableProxyServerNameserverPolicy = true;
                    uiState.value.dnsProxyServerNameserverPolicy = formatYamlMapText(data.dns['proxy-server-nameserver-policy']);
                } else {
                    uiState.value.enableProxyServerNameserverPolicy = false;
                    uiState.value.dnsProxyServerNameserverPolicy = '';
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
                uiState.value.enableNameserverPolicy = false;
                uiState.value.dnsNameserverPolicy = '';
                uiState.value.enableProxyServerNameserverPolicy = false;
                uiState.value.dnsProxyServerNameserverPolicy = '';
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
                    if (!Array.isArray(p.payload)) return;
                    if (!data.proxies) data.proxies = [];
                    p.payload.forEach(px => {
                        if (!px || typeof px !== 'object') return;
                        if (!data.proxies.find(x => x.name === px.name)) data.proxies.push(px);
                    });
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
                    const payloadNodes = Array.isArray(p.payload)
                        ? p.payload.filter(isPlainObject).map((item) => safeJsonClone(item, {}))
                        : [];
                    const payloadProxyNames = payloadNodes
                        .map(px => String(px?.name || '').trim())
                        .filter(Boolean);
                    const rawOverride = isPlainObject(p.override) ? p.override : {};
                    const prov = {
                        name: k,
                        type: p.type || 'http',
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
                        healthCheckLazy: true,
                        healthCheckTimeout: 5000,
                        healthExpectedStatus: '',
                        lazy: true,
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
                        _unsupportedOverride: {}
                    };

                    prov.path = p.path || '';
                    prov.proxy = p.proxy || '';
                    prov.sizeLimit = p['size-limit'] !== undefined && p['size-limit'] !== null ? String(p['size-limit']) : '';
                    prov.ageSecretKey = p['age-secret-key'] || '';
                    prov.headers = formatYamlMapText(p.header);
                    prov.filter = p.filter || '';
                    prov.excludeFilter = p['exclude-filter'] || '';
                    prov.excludeType = p['exclude-type'] || '';

                    if (isPlainObject(p.override)) {
                        const handledOverrideKeys = new Set();
                        const assignStringOverride = (overrideKey, stateKey) => {
                            if (!Object.prototype.hasOwnProperty.call(rawOverride, overrideKey)) return;
                            const rawValue = rawOverride[overrideKey];
                            if (Array.isArray(rawValue) || isPlainObject(rawValue)) return;
                            prov[stateKey] = String(rawValue ?? '').trim();
                            handledOverrideKeys.add(overrideKey);
                        };
                        const assignBooleanOverride = (overrideKey, stateKey) => {
                            if (!Object.prototype.hasOwnProperty.call(rawOverride, overrideKey)) return;
                            const rawValue = rawOverride[overrideKey];
                            if (rawValue !== true && rawValue !== false) return;
                            prov[stateKey] = formatProviderOverrideBooleanValue(rawValue);
                            handledOverrideKeys.add(overrideKey);
                        };

                        assignStringOverride('dialer-proxy', 'overrideDialerProxy');
                        assignStringOverride('additional-prefix', 'overrideAdditionalPrefix');
                        assignStringOverride('additional-suffix', 'overrideAdditionalSuffix');
                        if (Object.prototype.hasOwnProperty.call(rawOverride, 'proxy-name')) {
                            prov.overrideProxyName = formatYamlSequenceText(rawOverride['proxy-name']);
                            handledOverrideKeys.add('proxy-name');
                        }
                        assignBooleanOverride('udp', 'overrideUdp');
                        assignBooleanOverride('udp-over-tcp', 'overrideUdpOverTcp');
                        assignBooleanOverride('tfo', 'overrideTfo');
                        assignBooleanOverride('mptcp', 'overrideMptcp');
                        assignBooleanOverride('skip-cert-verify', 'overrideSkipCertVerify');
                        assignStringOverride('up', 'overrideUp');
                        assignStringOverride('down', 'overrideDown');
                        assignStringOverride('interface-name', 'overrideInterfaceName');
                        assignStringOverride('routing-mark', 'overrideRoutingMark');
                        assignStringOverride('ip-version', 'overrideIpVersion');

                        const unsupportedOverride = Object.keys(rawOverride).reduce((acc, key) => {
                            const normalizedKey = String(key || '').trim();
                            if (!normalizedKey || handledOverrideKeys.has(normalizedKey)) return acc;
                            acc[normalizedKey] = safeJsonClone(rawOverride[key], rawOverride[key]);
                            return acc;
                        }, {});
                        prov._unsupportedOverride = unsupportedOverride;
                        prov._unsupportedOverrideKeys = Object.keys(unsupportedOverride);
                    }

                    if (prov.type === 'http' || prov.type === 'file') {
                        prov.interval = p.interval || 3600;
                        prov.lazy = p.lazy !== false;
                        prov.healthCheckEnable = p['health-check']?.enable !== false;
                        prov.healthUrl = p['health-check']?.url || 'https://www.gstatic.com/generate_204';
                        prov.healthCheckInterval = p['health-check']?.interval || 600;
                        prov.healthCheckLazy = p['health-check']?.lazy !== false;
                        prov.healthCheckTimeout = p['health-check']?.timeout || 5000;
                        prov.healthExpectedStatus = p['health-check']?.['expected-status'] || '';
                    }

                    if (prov.type === 'http') {
                        prov.url = p.url || '';
                    } else if (prov.type === 'inline') {
                        prov.inlineProxies = payloadProxyNames;
                    } else if (payloadNodes.length > 0) {
                        prov._fallbackPayload = payloadNodes;
                        prov._fallbackPayloadProxyNames = payloadProxyNames;
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
                        format: p.format || 'mrs',
                        interval: p.interval || 86400,
                        autoUrl: false,
                        customUrl: '',
                        path: p.path || '',
                        pathInBundle: p['path-in-bundle'] || '',
                        proxy: p.proxy || '',
                        sizeLimit: p['size-limit'] !== undefined && p['size-limit'] !== null ? String(p['size-limit']) : '',
                        headers: formatYamlMapText(p.header),
                        file: '',
                        payload: '',
                        _collapsed: false
                    };

                    if (rp.type === 'http') {
                        rp.customUrl = p.url || '';
                        if (rp.behavior !== 'classical' && rp.customUrl.includes('meta-rules-dat')) {
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
                        'exclude-type': g['exclude-type'] || '',
                        url: g.url || 'https://www.gstatic.com/generate_204',
                        interval: g.interval || 300,
                        tolerance: g.tolerance || 50,
                        timeout: g.timeout || 0,
                        lazy: g.lazy !== false,
                        'max-failed-times': Number.isFinite(Number(g['max-failed-times'])) ? Number(g['max-failed-times']) : 5,
                        'disable-udp': g['disable-udp'] === true,
                        'interface-name': g['interface-name'] || '',
                        'routing-mark': g['routing-mark'] !== undefined && g['routing-mark'] !== null ? String(g['routing-mark']) : '',
                        strategy: g.strategy || 'consistent-hashing',
                        'include-all': g['include-all'] === true,
                        'include-all-proxies': g['include-all-proxies'] === true,
                        'include-all-providers': g['include-all-providers'] === true,
                        'expected-status': g['expected-status'] || '',
                        'empty-fallback': g['empty-fallback'] || '',
                        hidden: g.hidden === true,
                        icon: g.icon || '',
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

        const ensureRuntimeExportAllowed = () => {
            const errors = Array.isArray(runtimeValidationErrors && runtimeValidationErrors.value)
                ? runtimeValidationErrors.value
                : [];
            if (errors.length === 0) return true;

            const summary = errors.length > 1
                ? `当前配置校验未通过，共发现 ${errors.length} 个错误。`
                : '当前配置校验未通过。';
            alert(`${summary}\n\n首个错误：${errors[0]}\n\n请先修复右侧 YAML 预览区中的运行时校验错误。`);
            return false;
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
            if (!ensureRuntimeExportAllowed()) return;
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
            if (!ensureRuntimeExportAllowed()) return;
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
