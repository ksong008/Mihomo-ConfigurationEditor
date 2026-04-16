(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createYamlModule = function (ctx) {
        const { ref, config, uiState, providersList, ruleProvidersList, parseSingleProxyNode, getRuleProviderUrl } = ctx;
        const { parsePorts, parseHosts, parseYamlMapText, parseMarkValue, getListenPort } = window.MihomoHelpers;

        const yamlSections = ref({ general: '', network: '', proxies: '', providers: '', ruleProviders: '', groups: '', rules: '' });
        const fullYaml = ref('');

        const buildYaml = () => {
            try {
                const raw = JSON.parse(JSON.stringify(config.value));
                const parseText = (text) => text ? (text||'').split('\n').map(s => s.trim()).filter(Boolean) : [];
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
                if (raw.secret) outGeneral.secret = raw.secret;
                if (raw['external-ui-url']) { outGeneral['external-ui'] = raw['external-ui']; outGeneral['external-ui-url'] = raw['external-ui-url']; }
                if (raw['interface-name']) outGeneral['interface-name'] = raw['interface-name'];
                if (raw['geodata-mode'] !== undefined) outGeneral['geodata-mode'] = raw['geodata-mode'];

                if (raw.geo) {
                    outGeneral['geo-auto-update'] = raw.geo['auto-update'];
                    outGeneral['geo-update-interval'] = raw.geo.interval;
                    outGeneral['geox-url'] = raw.geo.url;
                }

                if (raw['unified-delay'] !== undefined) outGeneral['unified-delay'] = raw['unified-delay'];
                if (raw['tcp-concurrent'] !== undefined) outGeneral['tcp-concurrent'] = raw['tcp-concurrent'];

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

                if (finalListeners.length > 0) outGeneral.listeners = finalListeners;

                let outNetwork = {};
                if (raw.tun && raw.tun.enable) {
                    outNetwork.tun = {
                        enable: true, stack: raw.tun.stack, 'auto-route': raw.tun['auto-route'], 'auto-detect-interface': raw.tun['auto-detect-interface']
                    };
                    if (raw.tun.device && raw.tun.device.trim() !== '') outNetwork.tun.device = raw.tun.device.trim();
                    if (raw.tun.mtu) outNetwork.tun.mtu = raw.tun.mtu;
                    if (raw.tun.gso !== undefined) outNetwork.tun.gso = raw.tun.gso;
                    if (raw.tun.gso && raw.tun['gso-max-size']) outNetwork.tun['gso-max-size'] = raw.tun['gso-max-size'];
                    if (raw.tun['strict-route'] !== undefined) outNetwork.tun['strict-route'] = raw.tun['strict-route'];
                    if (raw.tun['endpoint-independent-nat'] !== undefined) outNetwork.tun['endpoint-independent-nat'] = raw.tun['endpoint-independent-nat'];

                    const hijack = uiState.value.tunDnsHijackEnabled
                        ? (uiState.value.tunDnsHijack||'').split('\n').map(s=>s.trim()).filter(Boolean)
                        : [];
                    if (uiState.value.tunDnsHijackEnabled && hijack.length > 0) outNetwork.tun['dns-hijack'] = hijack;
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
                        if (sHTTP.length > 0) outNetwork.sniffer.sniff.HTTP = { ports: sHTTP };
                        if (sTLS.length > 0) outNetwork.sniffer.sniff.TLS = { ports: sTLS };
                        if (sQUIC.length > 0) outNetwork.sniffer.sniff.QUIC = { ports: sQUIC };
                    }
                    const skips = parseText(uiState.value.snifferSkipDomain);
                    if(skips.length > 0) outNetwork.sniffer['skip-domain'] = skips;
                    const forces = parseText(uiState.value.snifferForceDomain);
                    if(forces.length > 0) outNetwork.sniffer['force-domain'] = forces;
                    const whitelists = parseText(uiState.value.snifferPortWhitelist);
                    if(whitelists.length > 0) outNetwork.sniffer['port-whitelist'] = whitelists.map(p => isNaN(p) ? p : Number(p));
                }

                if (raw.dns && raw.dns.enable) {
                    outNetwork.dns = { ...raw.dns };
                    const normalizedDnsListen = getListenPort(raw.dns.listen, 53);
                    outNetwork.dns.listen = `:${normalizedDnsListen}`;
                    if (outNetwork.dns['enhanced-mode'] === 'fake-ip') {
                        outNetwork.dns['fake-ip-filter-mode'] = raw.dns['fake-ip-filter-mode'];
                        const filters = parseText(uiState.value.fakeIpFilter);
                        if (filters.length > 0) outNetwork.dns['fake-ip-filter'] = filters;
                    } else { delete outNetwork.dns['fake-ip-range']; delete outNetwork.dns['fake-ip-filter-mode']; }

                    outNetwork.dns['default-nameserver'] = parseText(uiState.value.dnsDefaultNameservers);
                    outNetwork.dns.nameserver = parseText(uiState.value.dnsNameservers);
                    if (uiState.value.enableDnsFallback) {
                        outNetwork.dns.fallback = parseText(uiState.value.dnsFallback);
                    } else {
                        delete outNetwork.dns.fallback;
                    }
                    outNetwork.dns['proxy-server-nameserver'] = parseText(uiState.value.dnsProxyServerNameservers);
                    outNetwork.dns['direct-nameserver'] = parseText(uiState.value.dnsDirectNameservers);

                    if (uiState.value.enableNameserverPolicy) {
                        const parsedPolicy = parseYamlMapText(uiState.value.dnsNameserverPolicy);
                        if (parsedPolicy) outNetwork.dns['nameserver-policy'] = parsedPolicy;
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
                const normalizeDialerProxy = (value) => value && validStaticMembers.has(value) ? value : '';
                let outProxies = {};
                if (raw.proxies && raw.proxies.length > 0) {
                    outProxies.proxies = raw.proxies.map(px => parseSingleProxyNode(px)).filter(Boolean);
                }

                let outProviders = {};
                if (providersList.value && providersList.value.length > 0) {
                    outProviders['proxy-providers'] = {};
                    providersList.value.forEach(p => {
                        if (p.name) {
                            let prov = { type: p.type || 'http' };
                            if (prov.type === 'http') {
                                if (!p.url) return;
                                prov.url = p.url;
                                prov.interval = p.interval || 3600;
                                if (p.lazy !== undefined) prov.lazy = p.lazy;
                                prov.path = `./providers/${p.name}.yaml`;
                                prov['health-check'] = {
                                    enable: true, interval: 600, url: p.healthUrl || 'https://www.gstatic.com/generate_204',
                                    lazy: p.healthCheckLazy !== false, timeout: p.healthCheckTimeout || 5000
                                };
                                const normalizedDownloadProxy = normalizeDialerProxy(p.downloadProxy);
                                if (p.useDownloadProxy && normalizedDownloadProxy) prov['dialer-proxy'] = normalizedDownloadProxy;
                            } else if (prov.type === 'inline') {
                                let payloadNodes = [];
                                if (p.inlineProxies && p.inlineProxies.length > 0) {
                                    payloadNodes = p.inlineProxies.map(pxName => parseSingleProxyNode((raw.proxies||[]).find(x => x.name === pxName))).filter(Boolean);
                                }
                                prov.payload = payloadNodes;
                                const normalizedOverrideDialerProxy = normalizeDialerProxy(p.overrideDialerProxy);
                                if (normalizedOverrideDialerProxy) prov.override = { 'dialer-proxy': normalizedOverrideDialerProxy };
                            }
                            outProviders['proxy-providers'][p.name] = prov;
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
                            rProv.path = `./rules/${rp.name}.${rp.format}`;
                            rProv.url = url;
                            rProv.interval = rp.interval || 86400;
                        } else if (rp.type === 'file') {
                            rProv.path = rp.path || `./rules/${rp.name}.${rp.format}`;
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
                        if (g['include-all']) cg['include-all'] = true;

                        if(g.type === 'load-balance') cg.strategy = g.strategy || 'consistent-hashing';

                        if(g.type !== 'relay') {
                            if(!cg['include-all']) {
                                if(g.proxies && g.proxies.length>0) cg.proxies = g.proxies.filter(name => validStaticMembers.has(name));
                                if(g.use && g.use.length>0) cg.use = g.use.filter(name => providerNames.includes(name));
                            }
                            if(g.filter) cg.filter = g.filter;
                            if(g['exclude-filter']) cg['exclude-filter'] = g['exclude-filter'];
                        } else {
                            if(g.proxies && g.proxies.length>0) cg.proxies = g.proxies;
                        }

                        if(g.type === 'url-test' || g.type === 'fallback' || g.type === 'load-balance') {
                            cg.url = g.url || 'https://www.gstatic.com/generate_204';
                            cg.interval = g.interval || 300;
                        }
                        if(g.type === 'url-test' || g.type === 'fallback') {
                            if (g.timeout > 0) cg.timeout = g.timeout;
                        }
                        if(g.type === 'url-test') { cg.tolerance = g.tolerance; cg.lazy = g.lazy; }
                        const normalizedGroupDialerProxy = normalizeDialerProxy(g['dialer-proxy']);
                        if(normalizedGroupDialerProxy) cg['dialer-proxy'] = normalizedGroupDialerProxy;

                        if (cg.type === 'relay') {
                            delete cg.url; delete cg.interval; delete cg.timeout; delete cg.tolerance; delete cg.lazy;
                        }
                        return cg;
                    });
                } else { outGroups['proxy-groups'] = [{ name: 'Proxy', type: 'select', proxies: ['DIRECT'] }]; }

                let outRules = { rules: [] };
                if (uiState.value.rules) {
                    outRules.rules = uiState.value.rules.map(r => {
                        const ipTypes = ['GEOIP', 'IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'IP-SUFFIX', 'IP-ASN', 'SRC-IP-SUFFIX', 'SRC-IP-ASN'];
                        if (r.logic) {
                            const parts = (r.conditions||[]).map(c => {
                                let innerVal = c.type === 'DOMAIN-REGEX' && c.value && c.value.includes(',') ? `"${c.value}"` : c.value;
                                let inner = `${c.type},${innerVal}`;
                                if (c.noResolve && ipTypes.includes(c.type)) inner += ',no-resolve';
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
                            return `NOT,((${inner})),${normalizeRuleTarget(r.target)}`;
                        } else {
                            let ruleStr = `${inner},${normalizeRuleTarget(r.target)}`;
                            if (r.noResolve && ipTypes.includes(r.type)) ruleStr += ',no-resolve';
                            return ruleStr;
                        }
                    });
                }
                if (!outRules.rules.some(r => r.startsWith('MATCH'))) outRules.rules.push(`MATCH,${defaultRuleTarget}`);

                const dump = (obj) => Object.keys(obj).length > 0 ? jsyaml.dump(obj, opts) : '';

                yamlSections.value = {
                    general: dump(outGeneral), network: dump(outNetwork),
                    proxies: dump(outProxies), providers: dump(outProviders), ruleProviders: dump(outRuleProviders),
                    groups: dump(outGroups), rules: dump(outRules)
                };

                fullYaml.value = [yamlSections.value.general, yamlSections.value.network, yamlSections.value.proxies, yamlSections.value.providers, yamlSections.value.ruleProviders, yamlSections.value.groups, yamlSections.value.rules].filter(Boolean).join('');
            } catch (err) {
                console.error("YAML 构建遭遇异常:", err);
            }
        };

        return {
            yamlSections,
            fullYaml,
            buildYaml
        };
    };
})(window);
