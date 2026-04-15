(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 mihomo.helpers.js');
    }

    const { createApp, ref, computed, watch, onMounted, nextTick, onErrorCaptured } = Vue;
    const {
        parsePorts,
        parseHosts,
        parseMarkValue,
        getListenPort,
        parseLineList,
        parseCommaList,
        DEFAULT_NFT_PRIVATE4,
        DEFAULT_NFT_PRIVATE6,
        DEFAULT_NFT_COMMON_PORTS,
        normalizeNftablesConfig,
        getSanitizedUiStateForSave,
        splitByComma,
        deepMerge
    } = window.MihomoHelpers;

createApp({
    setup() {
        const crashError = ref(null);

        onErrorCaptured((err, instance, info) => {
            console.error('UI渲染层捕获到异常，已自动拦截以防止白屏:', err, info);
            crashError.value = `Error: ${err.message}\nInfo: ${info}\nStack: ${err.stack}`;
            return false;
        });

        const forceClearCache = () => {
            localStorage.removeItem('mihomo_web_config_v17');
            location.reload();
        };

        const askConfirm = (msg) => {
            return window.confirm(msg);
        };

        const tabs = [
            { id: 'general', name: '系统管控', icon: 'fas fa-sliders-h' },
            { id: 'network', name: '网络解析', icon: 'fas fa-network-wired' },
            { id: 'providers', name: '订阅/节点', icon: 'fas fa-link' },
            { id: 'rule-providers', name: '规则集合', icon: 'fas fa-book-open' },
            { id: 'groups', name: '策略分流', icon: 'fas fa-layer-group' },
            { id: 'rules', name: '路由规则', icon: 'fas fa-route' },
            { id: 'tproxy', name: 'Tproxy代理', icon: 'fas fa-project-diagram' }
        ];
        const currentTab = ref('general');
        const yamlPreviewBox = ref(null);
        const fileInput = ref(null);

        const renderStatus = ref('实时渲染');
        const isLocating = ref(false);
        let scrollTimeout = null;

        const panels = [
            { id: 'zashboard', name: 'Zashboard', icon: 'fas fa-tachometer-alt', rawUrl: 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip', mirrorUrl: 'https://fastly.jsdelivr.net/gh/Zephyruso/zashboard@gh-pages/dist-cdn-fonts.zip' },
            { id: 'metacubexd', name: 'MetaCubeX-D', icon: 'fas fa-cube', rawUrl: 'https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip', mirrorUrl: 'https://fastly.jsdelivr.net/gh/MetaCubeX/metacubexd@gh-pages/metacubexd-gh-pages.zip' },
            { id: 'yacd-meta', name: 'Yacd-meta', icon: 'fas fa-chart-bar', rawUrl: 'https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip', mirrorUrl: 'https://fastly.jsdelivr.net/gh/MetaCubeX/Yacd-meta@gh-pages/Yacd-meta-gh-pages.zip' },
            { id: 'custom', name: '自定义', icon: 'fas fa-link', rawUrl: '', mirrorUrl: '' }
        ];

        const uiState = ref({
            useMirrorForPanels: true, selectedPanel: '', useMirrorForGeo: true, useMirrorForRuleProviders: true, showInstallScript: false, showSystemdService: false,
            tunDnsHijackEnabled: true,
            tunDnsHijack: "any:53\ntcp://any:53",
            tproxyEnable: false, showTproxyConflict: false, tproxyConflicts: [], pendingAction: '',
                        nftablesConfig: {
                nftTable: 'mihomo',
                tproxyPort: 7894, listen: '0.0.0.0', udp: true, tproxyIpv6: false,
                ingressIface: '', egressIface: '',
                routeMarkHex: '112', tproxyMarkHex: '111',
                proxyUid: '', proxyGid: '',
                hijackDns: true,
                privateIps: "0.0.0.0/8\n10.0.0.0/8\n100.64.0.0/10\n127.0.0.0/8\n169.254.0.0/16\n172.16.0.0/12\n192.0.0.0/24\n192.0.2.0/24\n192.88.99.0/24\n192.168.0.0/16\n198.51.100.0/24\n203.0.113.0/24\n224.0.0.0/4\n240.0.0.0/4",
                privateIpsV6: "::/128\n::1/128\nfc00::/7\nfe80::/10\n2001:db8::/32\n64:ff9b::/96\n100::/64\nff00::/8",
                bypassCnIp: false, cnIps: '', cnIpsV6: '', filterPorts: false, commonPorts: '22,587,465,995,993,143,80,443,853,9418'
            },
            snifferSniff: { HTTP: "80, 8080-8880", TLS: "443, 8443", QUIC: "443, 8443" },
            snifferSkipDomain: "Mijia Cloud\n*.apple.com", snifferForceDomain: "", snifferPortWhitelist: "",
            fakeIpFilter: "*.lan\n*.local\ntime.*.com\nntp.*.com\n*.msftconnecttest.com",
            hosts: "", dnsNameserverPolicy: "",
            useLocalDns53Forward: false,
            enableDnsFallback: false,
            dnsDefaultNameservers: "223.5.5.5\n119.29.29.29\n1.1.1.1\n8.8.8.8", dnsNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
            dnsFallback: "https://dns.google/dns-query\nhttps://cloudflare-dns.com/dns-query", dnsProxyServerNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query", dnsDirectNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
            fallbackFilterGeositeEnable: true, fallbackFilterGeosite: "gfw", fallbackFilterIpcidr: "240.0.0.0/4\n0.0.0.0/32", fallbackFilterDomain: "+.google.com\n+.facebook.com",
            rules: [
                { type: 'GEOSITE', value: 'category-ads-all', target: 'REJECT', noResolve: false, not: false },
                { type: 'GEOSITE', value: 'google', target: 'Proxy', noResolve: false, not: false },
                { type: 'GEOIP', value: 'cn', target: 'DIRECT', noResolve: true, not: false },
                { type: 'MATCH', value: '', target: 'Proxy', noResolve: false, not: false }
            ]
        });

        const getDefaultConfig = () => ({
            'mixed-port': 7890, port: 7891, 'socks-port': 7892, 'redir-port': 7893, 'tproxy-port': 7894,
            listeners: [],
            'routing-mark': 112, 'allow-lan': true, mode: 'rule', 'log-level': 'info', ipv6: false, 'global-client-fingerprint': '',
            'find-process-mode': 'strict', profile: { 'store-selected': true, 'store-fake-ip': true },
            'external-controller': '127.0.0.1:9090', secret: '', 'external-ui': 'ui', 'external-ui-url': '',
            'interface-name': '', 'geodata-mode': true, 'unified-delay': true, 'tcp-concurrent': true,
            tun: { enable: false, stack: 'system', device: '', mtu: 1500, gso: false, 'gso-max-size': 65536, 'auto-route': true, 'strict-route': true, 'auto-detect-interface': true, 'endpoint-independent-nat': false, 'dns-hijack': ['any:53', 'tcp://any:53'] },
            sniffer: { enable: false, 'force-dns-mapping': true, 'parse-pure-ip': true, 'override-destination': false },
            dns: { enable: true, listen: '53', ipv6: false, 'enhanced-mode': 'redir-host', 'fake-ip-range': '198.18.0.1/16', 'fake-ip-filter-mode': 'blacklist', 'prefer-h3': false, 'respect-rules': false, 'use-hosts': false, 'use-system-hosts': false, 'direct-nameserver-follow-policy': false, 'fallback-filter': { geoip: true, 'geoip-code': 'CN' } },
            geo: {
                'auto-update': true, interval: 24,
                url: {
                    geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
                    geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
                    mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb'
                }
            },
            proxies: [],
            'proxy-groups': [
                { name: 'Proxy', type: 'select', proxies: ['自动选择', '香港节点', '台湾节点', '韩国节点', '日本节点', '新加坡节点', '美国节点', '其他国家', 'DIRECT'], use: [], filter: '', 'exclude-filter': '', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, lazy: false, 'dialer-proxy': '', 'include-all': false },
                { name: '自动选择', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false },
                { name: '香港节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)港|hk|hongkong|hong kong', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false },
                { name: '台湾节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)台|tw|taiwan', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false },
                { name: '韩国节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)韩|kr|korea|south korea', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false },
                { name: '日本节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)日|jp|japan', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false },
                { name: '新加坡节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)新|sg|singapore', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false },
                { name: '美国节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)美|us|united states|america', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false },
                { name: '其他国家', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)^(?!.*(?:港|hk|台|tw|韩|kr|日|jp|新|sg|美|us)).*$', 'exclude-filter': '', tolerance: 50, lazy: true, 'dialer-proxy': '', 'include-all': false }
            ]
        });

        const config = ref(getDefaultConfig());
        const providersList = ref([]);
        const ruleProvidersList = ref([]);

        watch(() => uiState.value.useMirrorForPanels, (n) => {
            const p = panels.find(x => x.id === uiState.value.selectedPanel);
            if (p && p.id !== 'custom') config.value['external-ui-url'] = n ? p.mirrorUrl : p.rawUrl;
        });

        watch(() => uiState.value.useMirrorForGeo, (n) => {
            if (n) {
                config.value.geo.url = { geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat', geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat', mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb' };
            } else {
                config.value.geo.url = { geoip: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat', geosite: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat', mmdb: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/country.mmdb' };
            }
        });

        const resetGeoUrls = () => { uiState.value.useMirrorForGeo = true; config.value.geo.url = { geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat', geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat', mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb' }; };

        const normalizeDnsListenText = (val, fallback = '53') => {
            const raw = String(val ?? '').trim();
            const digits = raw.replace(/[^\d]/g, '');
            if (!digits) return fallback;
            let port = Number(digits);
            if (!Number.isInteger(port) || port < 1) port = 1;
            if (port > 65535) port = 65535;
            return String(port);
        };

        const dnsListenPortInput = computed({
            get() {
                return normalizeDnsListenText(config.value.dns && config.value.dns.listen, '53');
            },
            set(val) {
                if (!config.value.dns) config.value.dns = {};
                const digits = String(val ?? '').replace(/[^\d]/g, '');
                if (!digits) {
                    config.value.dns.listen = '';
                    return;
                }
                let port = Number(digits);
                if (!Number.isInteger(port) || port < 1) port = 1;
                if (port > 65535) port = 65535;
                config.value.dns.listen = String(port);
            }
        });

        const normalizeDnsListenInput = () => {
            if (!config.value.dns) return;
            config.value.dns.listen = normalizeDnsListenText(config.value.dns.listen, '53');
        };

        const dnsListenPort = computed(() => getListenPort(config.value.dns && config.value.dns.listen, 53));
        const showHostsEditor = computed(() => !!(config.value && config.value.dns && config.value.dns['use-hosts']));
        const usingTransparentProxy = computed(() => !!((config.value.tun && config.value.tun.enable) || uiState.value.tproxyEnable));

        const dnsHijackEnabled = computed(() => {
            const tunHijack = !!(config.value.tun && config.value.tun.enable && uiState.value.tunDnsHijackEnabled && String(uiState.value.tunDnsHijack || '').trim());
            const tproxyHijack = !!(uiState.value.tproxyEnable && uiState.value.nftablesConfig && uiState.value.nftablesConfig.hijackDns);
            return tunHijack || tproxyHijack;
        });

        const dnsForwardConflict = computed(() => !!(uiState.value.useLocalDns53Forward && dnsHijackEnabled.value));
        const dnsLocalForwardNeedsNon53 = computed(() => !!(uiState.value.useLocalDns53Forward && dnsListenPort.value === 53));

        const specifiedProxyPortList = computed(() =>
            parseCommaList((uiState.value.nftablesConfig && uiState.value.nftablesConfig.commonPorts) || '')
                .map(s => String(s).trim())
                .filter(Boolean)
        );

        const specifiedPortsContain53 = computed(() =>
            !!(uiState.value.nftablesConfig && uiState.value.nftablesConfig.filterPorts && specifiedProxyPortList.value.includes('53'))
        );

        const dnsPathPreview = computed(() => {
            const listen = `:${dnsListenPort.value}`;

            if (!(config.value.dns && config.value.dns.enable)) {
                return {
                    tone: 'slate',
                    title: 'DNS 当前未启用',
                    lines: [
                        'DNS 未启用，客户端会按系统原始 DNS 设置直接发送。',
                        '若你准备使用透明代理分流，建议开启内置 DNS。'
                    ]
                };
            }

            if (dnsForwardConflict.value) {
                return {
                    tone: 'amber',
                    title: '检测到 DNS 劫持与本地 53 转发同时开启',
                    lines: [
                        '客户端 -> 53 端口请求',
                        '-> 可能被 TUN / TProxy DNS 劫持接走',
                        '-> 也可能先到本机 53 前端再转发',
                        '建议：DNS 劫持 与 本地 53 前端转发 二选一'
                    ]
                };
            }

            if (uiState.value.useLocalDns53Forward) {
                return {
                    tone: dnsLocalForwardNeedsNon53.value ? 'amber' : 'emerald',
                    title: '使用本地 53 端口转发',
                    lines: [
                        '客户端 -> 192.168.1.1:53',
                        '-> 本机 53 前端服务 (dnsmasq / smartdns / AdGuard Home)',
                        `-> 127.0.0.1:${dnsListenPort.value}`,
                        '-> Mihomo 内置 DNS'
                    ]
                };
            }

            if (dnsHijackEnabled.value) {
                const mode = (config.value.tun && config.value.tun.enable) ? 'TUN dns-hijack' : 'TProxy DNS 劫持';
                return {
                    tone: 'emerald',
                    title: `${mode} 已接管 53 端口`,
                    lines: [
                        '客户端 -> 任意 DNS:53',
                        `-> ${mode}`,
                        `-> ${listen}`,
                        '-> Mihomo 内置 DNS'
                    ]
                };
            }

            if (usingTransparentProxy.value) {
                return {
                    tone: 'amber',
                    title: '透明代理已开启，但 DNS 未被接管',
                    lines: [
                        '客户端 -> 原始 DNS 服务器:53',
                        '-> 不经过 Mihomo 内置 DNS',
                        '如需稳定域名分流，请开启 DNS 劫持或使用本地 53 端口转发'
                    ]
                };
            }

            return {
                tone: 'slate',
                title: '按客户端原始 DNS 设置发送',
                lines: [
                    '当前既未启用透明代理 DNS 劫持，也未使用本地 53 端口转发。',
                    'DNS 行为取决于客户端自己的 DNS 配置。'
                ]
            };
        });

        const dns53WarnedKey = ref('');
        watch(
            () => [
                config.value.tun && config.value.tun.enable,
                uiState.value.tproxyEnable,
                config.value.dns && config.value.dns.enable,
                config.value.dns && config.value.dns.listen
            ].join('|'),
            () => {
                if (usingTransparentProxy.value && config.value.dns && config.value.dns.enable && dnsListenPort.value === 53) {
                    const key = [
                        config.value.tun && config.value.tun.enable ? 'tun' : '',
                        uiState.value.tproxyEnable ? 'tproxy' : '',
                        config.value.dns && config.value.dns.listen ? config.value.dns.listen : ':53'
                    ].join('|');

                    if (dns53WarnedKey.value !== key) {
                        dns53WarnedKey.value = key;
                        setTimeout(() => {
                            alert('检测到已启用 TUN 或 TProxy，而全局 DNS 监听端口仍为 53。\n\n请修改为其它端口，避免与本机 53 端口服务、DNS 劫持或本地 53 端口转发冲突。');
                        }, 0);
                    }
                } else {
                    dns53WarnedKey.value = '';
                }
            },
            { immediate: true }
        );

        watch(() => uiState.value.nftablesConfig?.tproxyIpv6, (val) => {
            if (!uiState.value.nftablesConfig) return;
            if (val && uiState.value.nftablesConfig.listen === '0.0.0.0') {
                uiState.value.nftablesConfig.listen = '::';
            } else if (!val && uiState.value.nftablesConfig.listen === '::') {
                uiState.value.nftablesConfig.listen = '0.0.0.0';
            }
        });

        watch(() => uiState.value.nftablesConfig?.routeMarkHex, (v) => {
            if (!uiState.value.nftablesConfig) return;
            config.value['routing-mark'] = parseMarkValue(v, 112);
        }, { immediate: true });

        watch(() => uiState.value.nftablesConfig?.egressIface, (v) => {
            if (!uiState.value.nftablesConfig) return;
            config.value['interface-name'] = (v || '').trim();
        }, { immediate: true });

        watch(() => config.value['tproxy-port'], (v) => {
            if (!uiState.value.nftablesConfig) return;
            uiState.value.nftablesConfig.tproxyPort = v || 7894;
        }, { immediate: true });

        const scrollToBottom = () => {
            nextTick(() => {
                const scrollBox = document.getElementById('main-scroll');
                if (scrollBox) { scrollBox.scrollTo({ top: scrollBox.scrollHeight, behavior: 'smooth' }); }
            });
        };

        const addListener = () => { config.value.listeners.push({ name: `listener-${config.value.listeners.length + 1}`, type: 'mixed', port: 7890, listen: '::', udp: true }); };
        const removeListener = (idx) => { config.value.listeners.splice(idx, 1); };

        const handleTproxyToggle = (e) => {
            if (uiState.value.tproxyEnable) {
                sanitizeNftMarks();
                let conflicts = [];
                if (config.value.tun && config.value.tun.enable) {
                    conflicts.push({ key: 'tun', desc: 'TUN 透明代理模式已开启 (TUN 与 Tproxy 可能会产生路由循环和冲突)' });
                }
                if (conflicts.length > 0) {
                    uiState.value.tproxyConflicts = conflicts;
                    uiState.value.pendingAction = 'tproxy';
                    uiState.value.showTproxyConflict = true;
                    uiState.value.tproxyEnable = false;
                }
            }
        };

        const handleTunToggle = (e) => {
            if (config.value.tun && config.value.tun.enable) {
                let conflicts = [];
                if (uiState.value.tproxyEnable) {
                    conflicts.push({ key: 'tproxy', desc: 'Tproxy 透明代理模式已开启 (TUN 与 Tproxy 可能会产生路由循环和冲突)' });
                }
                if (conflicts.length > 0) {
                    uiState.value.tproxyConflicts = conflicts;
                    uiState.value.pendingAction = 'tun';
                    uiState.value.showTproxyConflict = true;
                    config.value.tun.enable = false;
                }
            }
        };

        const cancelTproxyEnable = () => { uiState.value.showTproxyConflict = false; uiState.value.pendingAction = ''; };

        const resolveTproxyConflicts = () => {
            uiState.value.tproxyConflicts.forEach(c => {
                if (c.key === 'tun' && config.value.tun) config.value.tun.enable = false;
                if (c.key === 'tproxy') uiState.value.tproxyEnable = false;
            });
            uiState.value.showTproxyConflict = false;
            if (uiState.value.pendingAction === 'tproxy') {
                uiState.value.tproxyEnable = true;
            } else if (uiState.value.pendingAction === 'tun' && config.value.tun) {
                config.value.tun.enable = true;
            }
            uiState.value.pendingAction = '';
        };

        const RESERVED_ROUTE_TABLES = new Set([0, 253, 254, 255]);

        const nftMarkIssues = computed(() => {
            if (!uiState.value.nftablesConfig) return [];
            const issues = [];
            const proxyMark = parseMarkValue(uiState.value.nftablesConfig.tproxyMarkHex, 111);
            const routeMark = parseMarkValue(uiState.value.nftablesConfig.routeMarkHex, 112);

            if (RESERVED_ROUTE_TABLES.has(proxyMark)) issues.push(`代理 Mark ${proxyMark} 与保留路由表号冲突`);
            if (RESERVED_ROUTE_TABLES.has(routeMark)) issues.push(`路由 Mark ${routeMark} 与保留路由表号冲突`);
            if (proxyMark === routeMark) issues.push('代理 Mark 与路由 Mark 不能相同');
            return issues;
        });

        const sanitizeNftMarks = () => {
            if (!uiState.value.nftablesConfig) return;
            let proxyMark = parseMarkValue(uiState.value.nftablesConfig.tproxyMarkHex, 111);
            let routeMark = parseMarkValue(uiState.value.nftablesConfig.routeMarkHex, 112);

            if (RESERVED_ROUTE_TABLES.has(proxyMark)) proxyMark = 111;
            if (RESERVED_ROUTE_TABLES.has(routeMark)) routeMark = 112;
            if (proxyMark === routeMark) routeMark = proxyMark === 111 ? 112 : 111;

            uiState.value.nftablesConfig.tproxyMarkHex = String(proxyMark);
            uiState.value.nftablesConfig.routeMarkHex = String(routeMark);
        };

        const resetNftMarksSafe = () => {
            if (!uiState.value.nftablesConfig) return;
            uiState.value.nftablesConfig.tproxyMarkHex = '111';
            uiState.value.nftablesConfig.routeMarkHex = '112';
        };

        const formatConditions = (r) => {
            if (!r || !r.conditions) return '';
            return r.conditions.map(c => {
                if(!c) return '';
                let res = '';
                if (c.not) res += 'NOT ';
                res += c.type || '';
                if (c.value) res += ',' + c.value;
                return res;
            }).join(r.logic === 'AND' ? ' && ' : ' || ');
        };

        const routingCommands = computed(() => {
            const proxyMark = parseMarkValue(uiState.value.nftablesConfig?.tproxyMarkHex, 111);
            const ipv6 = !!uiState.value.nftablesConfig?.tproxyIpv6;

            let cmds = `ip rule add fwmark ${proxyMark} table ${proxyMark}\nip route add local default dev lo table ${proxyMark}`;
            if (ipv6) {
                cmds += `\nip -6 rule add fwmark ${proxyMark} table ${proxyMark}\nip -6 route add local default dev lo table ${proxyMark}`;
            }
            return cmds;
        });

        const copyCommands = async () => {
            try {
                await navigator.clipboard.writeText(routingCommands.value);
                alert('路由命令已复制');
            } catch(e){}
        };

        const systemdService = computed(() => {
            const nft = uiState.value.nftablesConfig || {};
            const nftTable = ((nft.nftTable || 'mihomo').trim() || 'mihomo').replace(/[^\w-]+/g, '_');
            const proxyMark = parseMarkValue(nft.tproxyMarkHex, 111);
            const ipv6 = !!nft.tproxyIpv6;

            let script = `[Unit]\nDescription=Mihomo TProxy Routing Rules\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n\n`;
            script += `# 启动前删除旧表（忽略不存在错误）\n`;
            script += `ExecStartPre=-/usr/sbin/nft delete table inet ${nftTable}\n`;
            script += `ExecStart=/usr/sbin/nft -f /etc/mihomo/tproxy.nft\n`;
            script += `ExecStart=/sbin/ip rule add fwmark ${proxyMark} table ${proxyMark}\n`;
            script += `ExecStart=/sbin/ip route add local default dev lo table ${proxyMark}\n`;
            if (ipv6) {
                script += `ExecStart=/sbin/ip -6 rule add fwmark ${proxyMark} table ${proxyMark}\n`;
                script += `ExecStart=/sbin/ip -6 route add local default dev lo table ${proxyMark}\n`;
            }

            script += `\n# 停止时删除路由与 nft 表（忽略不存在错误）\n`;
            script += `ExecStop=-/sbin/ip rule del fwmark ${proxyMark} table ${proxyMark}\n`;
            script += `ExecStop=-/sbin/ip route del local default dev lo table ${proxyMark}\n`;
            if (ipv6) {
                script += `ExecStop=-/sbin/ip -6 rule del fwmark ${proxyMark} table ${proxyMark}\n`;
                script += `ExecStop=-/sbin/ip -6 route del local default dev lo table ${proxyMark}\n`;
            }
            script += `ExecStop=-/usr/sbin/nft delete table inet ${nftTable}\n`;
            script += `\n[Install]\nWantedBy=multi-user.target`;
            return script;
        });

        const nftablesScript = computed(() => {
            const nft = uiState.value.nftablesConfig || {};

            const table = (((nft.nftTable || 'mihomo').trim()) || 'mihomo').replace(/[^\w-]+/g, '_');
            const tproxyPort = Number(config.value['tproxy-port'] || nft.tproxyPort || 7894);
            const dnsPort = getListenPort(config.value.dns && config.value.dns.listen, 53);

            const proxyMark = parseMarkValue(nft.tproxyMarkHex, 111);
            const routeMark = parseMarkValue(nft.routeMarkHex, 112);

            const ingressIface = (nft.ingressIface || '').trim();
            const egressIface = (nft.egressIface || config.value['interface-name'] || '').trim();

            const proxyUid = String(nft.proxyUid || '').trim();
            const proxyGid = String(nft.proxyGid || '').trim();
            const hasUidGid = !!(proxyUid && proxyGid);

            const ipv6 = !!nft.tproxyIpv6;
            const hijackDns = !!nft.hijackDns;
            const bypassCnIp = !!nft.bypassCnIp;
            const filterPorts = !!nft.filterPorts;

            const commonPorts = parseCommaList(nft.commonPorts).join(', ');
            const fakeIpRange = (config.value.dns && config.value.dns['enhanced-mode'] === 'fake-ip' && config.value.dns['fake-ip-range'])
                ? config.value.dns['fake-ip-range']
                : '';

            const private4 = parseLineList(nft.privateIps).filter(cidr => !fakeIpRange || cidr !== fakeIpRange);
            const private6 = parseLineList(nft.privateIpsV6);
            const cn4 = parseLineList(nft.cnIps);
            const cn6 = parseLineList(nft.cnIpsV6);

            const dnsBypassLine = hijackDns
                ? `        meta l4proto { tcp, udp } th dport 53 accept comment "DNS 交给 NAT/redirect 链处理"\n`
                : '';

            const portFilterRulesV4 = (filterPorts && commonPorts)
                ? (
                    fakeIpRange
                        ? `        ip daddr != ${fakeIpRange} tcp dport != { ${commonPorts} } accept comment "非 Fake-IP 的非常规 TCP 端口直连"\n        ip daddr != ${fakeIpRange} udp dport != { ${commonPorts} } accept comment "非 Fake-IP 的非常规 UDP 端口直连"\n`
                        : `        tcp dport != { ${commonPorts} } accept comment "非常规 TCP 端口直连"\n        udp dport != { ${commonPorts} } accept comment "非常规 UDP 端口直连"\n`
                )
                : '';

            let script = `#!/usr/sbin/nft -f

# table name: ${table}
# 若手动重复执行 nft -f 时提示 table already exists，可先执行：
#   nft delete table inet ${table}

table inet ${table} {
    set private_ip {
        type ipv4_addr
        flags interval
        elements = { ${private4.length ? private4.join(', ') : '127.0.0.0/8'} }
    }
`;

            if (ipv6) {
                script += `
    set private_ip6 {
        type ipv6_addr
        flags interval
        elements = { ${private6.length ? private6.join(', ') : '::1/128'} }
    }
`;
            }

            if (bypassCnIp && cn4.length) {
                script += `
    set cn_ip {
        type ipv4_addr
        flags interval
        elements = { ${cn4.join(', ')} }
    }
`;
            }

            if (bypassCnIp && ipv6 && cn6.length) {
                script += `
    set cn_ip6 {
        type ipv6_addr
        flags interval
        elements = { ${cn6.join(', ')} }
    }
`;
            }

            if (hijackDns) {
                script += `
    chain prerouting_dns {
        type nat hook prerouting priority dstnat; policy accept;
${ingressIface ? `        iifname != "lo" iifname != "${ingressIface}" accept comment "非指定入口接口放行"\n` : ''}        meta l4proto { tcp, udp } th dport 53 redirect to :${dnsPort} comment "DNS -> Mihomo DNS"
    }

    chain output_dns {
        type nat hook output priority dstnat; policy accept;
${hasUidGid ? `        meta skuid ${proxyUid} meta skgid ${proxyGid} accept comment "Mihomo 自身 DNS 请求放行"\n` : `        oifname "lo" accept comment "缺少 UID/GID 时仅放行 lo，避免最明显的 DNS 回环"\n`}        meta l4proto { tcp, udp } th dport 53 redirect to :${dnsPort} comment "本机 DNS -> Mihomo DNS"
    }
`;
            }

            script += `
    chain prerouting_tproxy {
        type filter hook prerouting priority mangle; policy accept;
${ingressIface ? `        iifname != "lo" iifname != "${ingressIface}" accept comment "非指定入口接口放行"\n` : ''}${dnsBypassLine}        fib daddr type local accept comment "发往本机地址的流量放行"
        ip daddr @private_ip accept comment "私有 IPv4 放行"
${bypassCnIp && cn4.length ? `        ip daddr @cn_ip accept comment "大陆 IPv4 放行"\n` : ''}${!ipv6 ? `        meta nfproto ipv6 accept comment "未启用 IPv6 TProxy"\n` : ''}${portFilterRulesV4}        meta l4proto { tcp, udp } th dport ${tproxyPort} reject with icmpx type host-unreachable comment "拒绝外部直接打到 TProxy 端口"
        meta l4proto tcp socket transparent 1 meta mark set ${proxyMark} accept comment "已由透明 socket 接管的 TCP 流量放行"
        meta l4proto { tcp, udp } tproxy to :${tproxyPort} meta mark set ${proxyMark} comment "导流到 Mihomo TProxy 端口"
    }

    chain output_tproxy {
        type route hook output priority mangle; policy accept;
${egressIface ? `        oifname != "${egressIface}" accept comment "非指定出口接口放行"\n` : ''}        ct direction reply accept comment "本机服务回包放行"\n        meta mark ${routeMark} accept comment "已打 route mark 的自身流量放行"
${hasUidGid ? `        meta skuid ${proxyUid} meta skgid ${proxyGid} meta mark set ${routeMark} accept comment "Mihomo 自身流量改打 route mark，避免回环"\n` : ''}${dnsBypassLine}        fib daddr type local accept comment "发往本机地址的流量放行"
        ip daddr @private_ip accept comment "私有 IPv4 放行"
${bypassCnIp && cn4.length ? `        ip daddr @cn_ip accept comment "大陆 IPv4 放行"\n` : ''}${!ipv6 ? `        meta nfproto ipv6 accept comment "未启用 IPv6 TProxy"\n` : ''}${portFilterRulesV4}        meta l4proto { tcp, udp } meta mark set ${proxyMark} comment "本机流量打 proxy mark，交给策略路由回注 lo"
    }
`;

            if (ipv6) {
                script += `
    chain prerouting_tproxy_v6 {
        type filter hook prerouting priority mangle; policy accept;
${ingressIface ? `        iifname != "lo" iifname != "${ingressIface}" accept comment "非指定入口接口放行"\n` : ''}${dnsBypassLine}        fib daddr type local accept comment "发往本机 IPv6 的流量放行"
        ip6 daddr @private_ip6 accept comment "私有 IPv6 放行"
${bypassCnIp && cn6.length ? `        ip6 daddr @cn_ip6 accept comment "大陆 IPv6 放行"\n` : ''}        meta l4proto { tcp, udp } th dport ${tproxyPort} reject with icmpx type host-unreachable comment "拒绝外部直接打到 TProxy 端口"
        meta l4proto tcp socket transparent 1 meta mark set ${proxyMark} accept comment "已由透明 socket 接管的 TCP 流量放行"
        meta l4proto { tcp, udp } tproxy to :${tproxyPort} meta mark set ${proxyMark} comment "导流到 Mihomo TProxy 端口"
    }

    chain output_tproxy_v6 {
        type route hook output priority mangle; policy accept;
${egressIface ? `        oifname != "${egressIface}" accept comment "非指定出口接口放行"\n` : ''}        ct direction reply accept comment "本机服务回包放行"\n        meta mark ${routeMark} accept comment "已打 route mark 的自身流量放行"
${hasUidGid ? `        meta skuid ${proxyUid} meta skgid ${proxyGid} meta mark set ${routeMark} accept comment "Mihomo 自身流量改打 route mark，避免回环"\n` : ''}${dnsBypassLine}        fib daddr type local accept comment "发往本机 IPv6 的流量放行"
        ip6 daddr @private_ip6 accept comment "私有 IPv6 放行"
${bypassCnIp && cn6.length ? `        ip6 daddr @cn_ip6 accept comment "大陆 IPv6 放行"\n` : ''}        meta l4proto { tcp, udp } meta mark set ${proxyMark} comment "本机 IPv6 流量打 proxy mark，交给策略路由回注 lo"
    }
`;
            }

            script += `}\n`;
            return script;
        });

        const getCleanNftables = () => { return nftablesScript.value; };

        const installScript = computed(() => {
            return `#!/bin/bash\n# 一键部署 Mihomo 透明代理持久化环境\nmkdir -p /etc/mihomo\n\n# 1. 写入 nftables 规则\ncat > /etc/mihomo/tproxy.nft << 'EOF'\n${getCleanNftables()}\nEOF\n\n# 2. 写入 Systemd 服务\ncat > /etc/systemd/system/mihomo-tproxy.service << 'EOF'\n${systemdService.value}\nEOF\n\n# 3. 重新加载并启用服务\nsystemctl daemon-reload\nsystemctl enable --now mihomo-tproxy\necho "Mihomo 透明代理规则已持久化部署并启动！"`;
        });

        const copyNftables = async () => { try { await navigator.clipboard.writeText(getCleanNftables()); alert('nftables 规则已复制'); } catch(e){} };
                const downloadNftables = () => {
            const url = URL.createObjectURL(new Blob([getCleanNftables()], { type: 'text/plain' }));
            const a = document.createElement('a');
            const fname = ((uiState.value.nftablesConfig?.nftTable || 'mihomo').trim() || 'mihomo').replace(/[^\w.-]+/g, '_');
            a.href = url;
            a.download = `${fname}.nft`;
            a.click();
            URL.revokeObjectURL(url);
        };
        const copyInstallScript = async () => { try { await navigator.clipboard.writeText(installScript.value); alert('部署脚本已复制'); } catch(e){} };


        const parseSingleProxyNode = (px) => {
            if (!px) return null;

            let portVal = px.port;
            if (typeof portVal === 'string' && !portVal.includes('-')) {
                const num = Number(portVal);
                if (!isNaN(num)) portVal = num;
            }

            const base = {
                name: px.name || `Node-${Math.floor(Math.random()*1000)}`,
                type: px.type || 'vless',
                server: px.server || '',
                port: portVal || 443,
                udp: px.udp !== false,
                tfo: px.tfo || false,
                ip: px.ip || '',
                'packet-encoding': px['packet-encoding'] || '',
                uuid: px.uuid || '',
                flow: px.flow || '',
                alterId: px.alterId || 0,
                password: px['auth-str'] || px.psk || px.password || '',
                username: px.username || '',
                cipher: px.cipher || 'auto',
                plugin: px.plugin || '',
                'plugin-opts': { mode: 'websocket', host: '', path: '/', tls: false, mux: false, password: '', ...(px['plugin-opts'] || {}) },
                'kcptun-opts': { crypt: 'aes-128-gcm', ...(px['kcptun-opts'] || {}) },
                protocol: px.protocol || '',
                'protocol-param': px['protocol-param'] || '',
                obfs: px.obfs || '',
                'obfs-param': px['obfs-param'] || '',
                version: px.version || '4',
                'public-key': px['public-key'] || '',
                'private-key': px['private-key'] || '',
                'pre-shared-key': px['pre-shared-key'] || '',
                reserved: px.reserved ? (typeof px.reserved === 'object' ? JSON.stringify(px.reserved) : px.reserved) : '',
                workers: px.workers || 2,
                mtu: px.mtu || 1420,
                'wg-dns': px.dns ? (Array.isArray(px.dns) ? px.dns.join(',') : px.dns) : '',
                up: px.up || '100 Mbps',
                down: px.down || '100 Mbps',
                'obfs-password': px['obfs-password'] || '',
                ports: px.ports || '',
                'hop-interval': px['hop-interval'] || '',
                'congestion-controller': px['congestion-controller'] || 'bbr',
                'udp-relay-mode': px['udp-relay-mode'] || 'native',
                'reduce-rtt': px['reduce-rtt'] || false,
                heartbeat: px.heartbeat || '10s',
                'request-timeout': px['request-timeout'] || '15s',
                'udp-over-tcp': px['udp-over-tcp'] || false,
                passphrase: px.passphrase || '',
                'obfs-host': px['obfs-host'] || '',
                network: px.network || 'tcp',
                tls: px.tls || false,
                'skip-cert-verify': px['skip-cert-verify'] || false,
                servername: px.servername || '',
                'client-fingerprint': px['client-fingerprint'] || '',
                alpn: px.alpn ? (Array.isArray(px.alpn) ? px.alpn.join(',') : px.alpn) : '',
                reality: !!(px['reality-opts'] && Object.keys(px['reality-opts']).length > 0) || !!px.reality,
                'reality-opts': { 'public-key': '', 'short-id': '', ...(px['reality-opts'] || {}) },
                smux: { enabled: !!(px.smux && px.smux.enabled), protocol: px.smux?.protocol || 'h2mux', 'max-connections': px.smux?.['max-connections'] || 4, padding: !!(px.smux?.padding) },
                'ws-opts': { path: px['ws-opts']?.path || '/', headers: { Host: px['ws-opts']?.headers?.Host || '' }, 'max-early-data': px['ws-opts']?.['max-early-data'] || 0, 'early-data-header-name': px['ws-opts']?.['early-data-header-name'] || 'Sec-WebSocket-Protocol' },
                'grpc-opts': { 'grpc-service-name': px['grpc-opts']?.['grpc-service-name'] || '' },
                'httpupgrade-opts': { host: px['httpupgrade-opts']?.host || '', path: px['httpupgrade-opts']?.path || '/' },
                'h2-opts': { host: px['h2-opts']?.host || '', path: px['h2-opts']?.path || '/' },
                'http-opts': { path: px['http-opts']?.path || '/', host: px['http-opts']?.host || '', headers: { Host: px['http-opts']?.headers?.Host || '' } },
                'xhttp-opts': { path: px['xhttp-opts']?.path || '/', host: px['xhttp-opts']?.host || '', mode: px['xhttp-opts']?.mode || 'auto' },
                'idle-session-check-interval': px['idle-session-check-interval'] || '30s',
                'idle-session-timeout': px['idle-session-timeout'] || '30s',
                'min-idle-session': px['min-idle-session'] || 0,
                transport: px.transport || 'TCP',
                multiplexing: px.multiplexing || 'MULTIPLEXING_OFF',
                'dialer-proxy': px['dialer-proxy'] || ''
            };

            if (base['h2-opts'] && Array.isArray(base['h2-opts'].host)) base['h2-opts'].host = base['h2-opts'].host.join(',');
            if (base['http-opts']) {
                if (Array.isArray(base['http-opts'].path)) base['http-opts'].path = base['http-opts'].path.join(',');
                if (base['http-opts'].headers && base['http-opts'].headers.Host) base['http-opts'].host = Array.isArray(base['http-opts'].headers.Host) ? base['http-opts'].headers.Host[0] : base['http-opts'].headers.Host;
            }
            if (px.type === 'tuic' && !base.uuid) base.uuid = px.uuid || '';
            return base;
        };

        const addManualProxy = () => { config.value.proxies.push(parseSingleProxyNode({ type: 'vless' })); scrollToBottom(); };
        const addGroup = () => { config.value['proxy-groups'].push({ name: `Group-${(config.value['proxy-groups']||[]).length + 1}`, type: 'select', proxies: [], use: [], filter: '', 'exclude-filter': '', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, timeout: 0, lazy: false, 'dialer-proxy': '', strategy: 'consistent-hashing', 'include-all': false }); scrollToBottom(); };
        const removeGroup = (idx) => { config.value['proxy-groups'].splice(idx, 1); };

        const getAvailableGroupMembers = (currentGroupName) => {
            let groups = (config.value['proxy-groups'] || []).map(g=>g.name);
            if (currentGroupName) groups = groups.filter(n => n !== currentGroupName);
            return ['DIRECT', 'REJECT', ...groups, ...(config.value.proxies || []).map(p=>p.name)];
        };

        const injectRegionGroups = () => {
            if (!config.value['proxy-groups']) config.value['proxy-groups'] = [];
            const regions = [
                { name: '香港节点', filter: '(?i)港|hk|hongkong|hong kong' },
                { name: '台湾节点', filter: '(?i)台|tw|taiwan' },
                { name: '韩国节点', filter: '(?i)韩|kr|korea|south korea' },
                { name: '日本节点', filter: '(?i)日|jp|japan' },
                { name: '新加坡节点', filter: '(?i)新|sg|singapore' },
                { name: '美国节点', filter: '(?i)美|us|united states|america' },
                { name: '其他国家', filter: '(?i)^(?!.*(?:港|hk|台|tw|韩|kr|日|jp|新|sg|美|us)).*$' }
            ];

            let mainGroup = config.value['proxy-groups'].find(g => g.name === 'Proxy');
            if (!mainGroup) {
                mainGroup = { name: 'Proxy', type: 'select', proxies: ['自动选择', 'DIRECT'], use: [], filter: '', 'exclude-filter': '', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, timeout: 0, lazy: false, 'dialer-proxy': '', strategy: 'consistent-hashing', 'include-all': false };
                config.value['proxy-groups'].unshift(mainGroup);
            }

            let autoGroup = config.value['proxy-groups'].find(g => g.name === '自动选择');
            if (!autoGroup) {
                autoGroup = { name: '自动选择', type: 'url-test', proxies: [], use: (providersList.value||[]).map(p=>p.name), filter: '', 'exclude-filter': '', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, timeout: 0, lazy: true, 'dialer-proxy': '', strategy: 'consistent-hashing', 'include-all': false };
                config.value['proxy-groups'].splice(1, 0, autoGroup);
            }

            regions.forEach(r => {
                if (!config.value['proxy-groups'].find(g => g.name === r.name)) {
                    config.value['proxy-groups'].push({
                        name: r.name, type: 'url-test', proxies: [], use: (providersList.value||[]).map(p=>p.name),
                        filter: r.filter, 'exclude-filter': '', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, timeout: 0, lazy: true, 'dialer-proxy': '', strategy: 'consistent-hashing', 'include-all': false
                    });
                }
                if (!mainGroup.proxies.includes(r.name)) mainGroup.proxies.push(r.name);
            });
            autoCategorizeProxies();
        };

        const autoCategorizeProxies = () => {
            if (!config.value['proxy-groups'] || !config.value.proxies) return;
            config.value['proxy-groups'].forEach(g => {
                if (g.filter && g.filter.trim() !== '') {
                    try {
                        let jsPattern = g.filter;
                        let flags = '';
                        if (jsPattern.startsWith('(?i)')) { jsPattern = jsPattern.substring(4); flags = 'i'; }
                        const regex = new RegExp(jsPattern, flags);

                        const matched = config.value.proxies.filter(px => regex.test(px.name)).map(px => px.name);
                        matched.forEach(name => {
                            if (!g.proxies) g.proxies = [];
                            if (!g.proxies.includes(name)) g.proxies.push(name);
                        });

                        (providersList.value||[]).forEach(prov => {
                            if (!g.use) g.use = [];
                            if (prov.name && !g.use.includes(prov.name)) g.use.push(prov.name);
                        });
                    } catch(e) {}
                }
            });
        };

        const addCondition = (r) => {
            if (!r.conditions) r.conditions = [];
            r.conditions.push({type:'DOMAIN',value:'',not:false,noResolve:false});
        };

        const addRule = (kind) => {
            if (!uiState.value.rules) uiState.value.rules = [];
            const matchIdx = uiState.value.rules.findIndex(r => r.type === 'MATCH' && !r.logic);
            let newRule;
            const fallbackTarget = (config.value['proxy-groups'] && config.value['proxy-groups'][0]) ? config.value['proxy-groups'][0].name : 'DIRECT';
            if (kind === 'AND' || kind === 'OR') {
                newRule = { logic: kind, not: false, target: fallbackTarget, conditions: [{ type: 'DOMAIN', value: '', not: false, noResolve: false }] };
            } else {
                newRule = { type: 'GEOSITE', value: '', target: fallbackTarget, noResolve: false, not: false };
            }
            if (matchIdx !== -1) uiState.value.rules.splice(matchIdx, 0, newRule);
            else uiState.value.rules.push(newRule);
            scrollToBottom();
        };

        const pickPanel = (p) => { uiState.value.selectedPanel = p.id; config.value['external-ui-url'] = uiState.value.useMirrorForPanels ? p.mirrorUrl : p.rawUrl; };
        const addProvider = () => { providersList.value.push({ name: `Provider-${(providersList.value||[]).length + 1}`, type: 'http', url: '', interval: 3600, healthUrl: 'https://www.gstatic.com/generate_204', overrideDialerProxy: '', useDownloadProxy: false, downloadProxy: '', inlineProxies: [], lazy: true, healthCheckLazy: true, healthCheckTimeout: 5000 }); scrollToBottom(); };
        const removeProvider = (idx) => providersList.value.splice(idx, 1);

        const addRuleProvider = () => { ruleProvidersList.value.push({ name: '', type: 'http', file: '', behavior: 'domain', format: 'yaml', interval: 86400, autoUrl: true, customUrl: '', path: '', payload: '' }); scrollToBottom(); };
        const removeRuleProvider = (idx) => ruleProvidersList.value.splice(idx, 1);

        const updateRuleProviderName = (rp, newName) => {
            const oldName = rp.name;
            rp.name = newName;
            if (oldName && oldName !== newName) {
                (uiState.value.rules||[]).forEach(r => {
                    if (r.type === 'RULE-SET' && r.value === oldName) r.value = newName;
                    if (r.logic && r.conditions) {
                        r.conditions.forEach(cond => { if (cond.type === 'RULE-SET' && cond.value === oldName) cond.value = newName; });
                    }
                });
            }
        };

        const getRuleProviderUrl = (rp) => {
            if (!rp.autoUrl) return rp.customUrl;
            const targetName = rp.file ? rp.file.trim() : '';
            if (!targetName) return '';
            const base = uiState.value.useMirrorForRuleProviders
                ? 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo'
                : 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo';
            const folder = rp.behavior === 'ipcidr' ? 'geoip' : 'geosite';
            return `${base}/${folder}/${targetName}.${rp.format}`;
        };

        const clearLists = () => {
            if(askConfirm('确定要清空所有的节点、订阅和规则列表吗？')) {
                config.value.proxies = []; config.value['proxy-groups'] = []; providersList.value = []; ruleProvidersList.value = []; uiState.value.rules = [];
            }
        };
        const draggedRuleIndex = ref(null);
        const onRuleDragStart = (idx, e) => { draggedRuleIndex.value = idx; e.dataTransfer.effectAllowed = 'move'; };
        const onRuleDragEnter = () => {}; const onRuleDragEnd = () => { draggedRuleIndex.value = null; (uiState.value.rules||[]).forEach(r => r.draggable = false); };
        const onRuleDrop = (idx) => { const from = draggedRuleIndex.value; if (from !== null && from !== idx && uiState.value.rules) { const item = uiState.value.rules.splice(from, 1)[0]; uiState.value.rules.splice(idx, 0, item); } onRuleDragEnd(); };

        const getInlinePayloadPreview = (inlineProxies) => {
            if (!inlineProxies || inlineProxies.length === 0) return '[]';
            const nodes = inlineProxies.map(name => {
                const px = (config.value.proxies||[]).find(x => x.name === name);
                if (!px) return null;
                const cleanPx = JSON.parse(JSON.stringify(parseSingleProxyNode(px)));
                return cleanPx;
            }).filter(Boolean);
            try {
                return jsyaml.dump(nodes, { indent: 2, lineWidth: -1, sortKeys: false });
            } catch (e) { return '# Preview Error'; }
        };

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

                    const parsedPolicy = parseHosts(uiState.value.dnsNameserverPolicy);
                    if (parsedPolicy) outNetwork.dns['nameserver-policy'] = parsedPolicy;

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

        let lastTarget = '';
        const handleFocus = (e) => {
            const el = e.target.closest('[data-yaml-target]');
            if (el) {
                const keyword = el.getAttribute('data-yaml-target');
                if (keyword && keyword !== lastTarget) {
                    lastTarget = keyword;
                    locateAndScroll(keyword);
                }
            }
        };

        const locateAndScroll = (keyword) => {
            if(!yamlPreviewBox.value) return;
            clearTimeout(scrollTimeout);
            isLocating.value = true;
            renderStatus.value = `追踪: ${keyword.trim().slice(0, 15)}...`;

            scrollTimeout = setTimeout(() => {
                const container = yamlPreviewBox.value;
                const lines = fullYaml.value.split('\n');
                const idx = lines.findIndex(l => l.includes(keyword));
                if(idx !== -1) {
                    const scrollHeight = container.querySelector('pre').getBoundingClientRect().height;
                    const lineHeight = scrollHeight / lines.length;
                    const targetY = Math.max(0, idx * lineHeight - 60);
                    container.scrollTo({ top: targetY, behavior: 'smooth' });
                }
                setTimeout(() => { isLocating.value = false; renderStatus.value = '实时渲染'; }, 1000);
            }, 100);
        };

        watch(currentTab, (newTab) => {
            if(!yamlPreviewBox.value) return;
            lastTarget = '';
            nextTick(() => {
                setTimeout(() => {
                    const el = document.getElementById('yaml-' + newTab);
                    if (el) {
                        const container = yamlPreviewBox.value;
                        const topPos = el.offsetTop - container.querySelector('pre').offsetTop;
                        container.scrollTo({ top: Math.max(0, topPos - 15), behavior: 'smooth' });
                    }
                }, 50);
            });
        });

        let buildTimeout;
        watch([config, uiState, providersList, ruleProvidersList], () => {
            const sanitizedUiState = getSanitizedUiStateForSave(uiState.value, config.value);
            localStorage.setItem('mihomo_web_config_v17', JSON.stringify({
                config: config.value, uiState: sanitizedUiState, providersList: providersList.value, ruleProvidersList: ruleProvidersList.value
            }));
            clearTimeout(buildTimeout);
            if (!isLocating.value) renderStatus.value = '实时渲染中...';
            buildTimeout = setTimeout(() => {
                buildYaml();
                if (!isLocating.value) renderStatus.value = '实时渲染';
            }, 150);
        }, { deep: true });

        const parseRuleString = (rStr) => {
            if (typeof rStr !== 'string') return null;
            let parts = splitByComma(rStr);

            if (['AND', 'OR'].includes(parts[0]) && parts.length === 3) {
                let logic = parts[0];
                let innerStr = parts[1].replace(/^\(+|\)+$/g, '');
                let target = parts[2];
                let condStrs = splitByComma(innerStr);
                let conditions = condStrs.map(c => {
                    let stripped = c.replace(/^\(+|\)+$/g, '');
                    let cParts = splitByComma(stripped);
                    let cNot = false;
                    if (cParts[0] === 'NOT') {
                        cNot = true;
                        cParts = splitByComma((cParts[1]||'').replace(/^\(+|\)+$/g, ''));
                    }
                    let val = (cParts[1]||'').replace(/^"|"$/g, '');
                    return { type: cParts[0], value: val, not: cNot, noResolve: cParts.includes('no-resolve') };
                });
                return { logic, not: false, target, conditions };
            }

            if (parts[0] === 'NOT' && parts.length === 3) {
                let innerStr = parts[1].replace(/^\(+|\)+$/g, '');
                let innerParts = splitByComma(innerStr);
                if (['AND', 'OR'].includes(innerParts[0])) {
                    let logicRule = parseRuleString(`${innerParts[0]},${innerParts[1]},${parts[2]}`);
                    if (logicRule) logicRule.not = true;
                    return logicRule;
                } else {
                    let cParts = innerParts;
                    let val = (cParts[1]||'').replace(/^"|"$/g, '');
                    return { type: cParts[0], value: val, target: parts[2], not: true, noResolve: cParts.includes('no-resolve') };
                }
            }

            if (parts[0] === 'MATCH') return { type: 'MATCH', value: '', target: parts[1] || 'DIRECT', noResolve: false, not: false };

            let val = (parts[1]||'').replace(/^"|"$/g, '');
            return { type: parts[0], value: val, target: parts[2], noResolve: parts.includes('no-resolve'), not: false };
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

        const triggerYamlImport = () => { fileInput.value.click(); };
        const handleYamlImport = (e) => {
            const file = e.target.files[0];
            if(!file) return;
            const reader = new FileReader();
            reader.onload = (ev) => {
                try {
                    const cleanText = ev.target.result.replace(/\xA0/g, ' ');
                    let parsed = jsyaml.load(cleanText);
                    parsed = resolveYamlMergeKeys(parsed);
                    applyYamlImport(parsed);
                    alert('YAML 导入成功！\n注意：原配置中的高级锚点已被展开。部分复杂自定义数据可能需要手动微调。');
                } catch(err) { alert('YAML 解析失败: ' + err.message); }
                e.target.value = '';
            };
            reader.readAsText(file);
        };

        const applyYamlImport = (data) => {
            if (!data) return;

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
                if(data.sniffer['force-dns-mapping'] !== undefined) config.value.sniffer['force-dns-mapping'] = data.sniffer['force-dns-mapping'];
                if(data.sniffer['parse-pure-ip'] !== undefined) config.value.sniffer['parse-pure-ip'] = data.sniffer['parse-pure-ip'];
                if(data.sniffer['override-destination'] !== undefined) config.value.sniffer['override-destination'] = data.sniffer['override-destination'];

                uiState.value.snifferSniff = { HTTP: '', TLS: '', QUIC: '' };
                if(data.sniffer.sniff) {
                    if (data.sniffer.sniff.HTTP && data.sniffer.sniff.HTTP.ports) uiState.value.snifferSniff.HTTP = data.sniffer.sniff.HTTP.ports.join(', ');
                    if (data.sniffer.sniff.TLS && data.sniffer.sniff.TLS.ports) uiState.value.snifferSniff.TLS = data.sniffer.sniff.TLS.ports.join(', ');
                    if (data.sniffer.sniff.QUIC && data.sniffer.sniff.QUIC.ports) uiState.value.snifferSniff.QUIC = data.sniffer.sniff.QUIC.ports.join(', ');
                }

                if(data.sniffer['skip-domain']) uiState.value.snifferSkipDomain = data.sniffer['skip-domain'].join('\n');
                if(data.sniffer['force-domain']) uiState.value.snifferForceDomain = data.sniffer['force-domain'].join('\n');
                if(data.sniffer['port-whitelist']) uiState.value.snifferPortWhitelist = data.sniffer['port-whitelist'].join('\n');
            } else config.value.sniffer.enable = false;

            if (data.dns) {
                config.value.dns.enable = true;
                ['listen', 'ipv6', 'enhanced-mode', 'fake-ip-range', 'fake-ip-filter-mode', 'prefer-h3', 'respect-rules', 'use-hosts', 'use-system-hosts', 'direct-nameserver-follow-policy'].forEach(k => {
                    if (data.dns[k] !== undefined) config.value.dns[k] = data.dns[k];
                });
                config.value.dns.listen = String(getListenPort(config.value.dns.listen, 53));
                if(data.dns['fake-ip-filter']) uiState.value.fakeIpFilter = data.dns['fake-ip-filter'].join('\n');
                if(data.dns['default-nameserver']) uiState.value.dnsDefaultNameservers = data.dns['default-nameserver'].join('\n');
                if(data.dns.nameserver) uiState.value.dnsNameservers = data.dns.nameserver.join('\n');
                const importedFallback = Array.isArray(data.dns.fallback)
                    ? data.dns.fallback
                    : (typeof data.dns.fallback === 'string' && data.dns.fallback.trim() ? [data.dns.fallback.trim()] : []);
                if (importedFallback.length > 0) {
                    uiState.value.enableDnsFallback = true;
                    uiState.value.dnsFallback = importedFallback.join('\n');
                } else {
                    uiState.value.enableDnsFallback = false;
                }
                if(data.dns['proxy-server-nameserver']) uiState.value.dnsProxyServerNameservers = data.dns['proxy-server-nameserver'].join('\n');
                if(data.dns['direct-nameserver']) uiState.value.dnsDirectNameservers = data.dns['direct-nameserver'].join('\n');

                if (data.dns['nameserver-policy']) {
                    uiState.value.dnsNameserverPolicy = Object.keys(data.dns['nameserver-policy']).map(k => `${k}: ${data.dns['nameserver-policy'][k]}`).join('\n');
                } else {
                    uiState.value.dnsNameserverPolicy = '';
                }

                if(data.dns['fallback-filter']) {
                    config.value.dns['fallback-filter'].geoip = data.dns['fallback-filter'].geoip !== false;
                    if(data.dns['fallback-filter']['geoip-code']) config.value.dns['fallback-filter']['geoip-code'] = data.dns['fallback-filter']['geoip-code'];

                    if(data.dns['fallback-filter'].geosite) {
                        uiState.value.fallbackFilterGeositeEnable = true;
                        uiState.value.fallbackFilterGeosite = data.dns['fallback-filter'].geosite.join('\n');
                    } else { uiState.value.fallbackFilterGeositeEnable = false; }

                    if(data.dns['fallback-filter'].ipcidr) uiState.value.fallbackFilterIpcidr = data.dns['fallback-filter'].ipcidr.join('\n');
                    if(data.dns['fallback-filter'].domain) uiState.value.fallbackFilterDomain = data.dns['fallback-filter'].domain.join('\n');
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
                    let prov = { name: k, type: p.type || 'http', overrideDialerProxy: '', inlineProxies: [] };

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
                    let rp = { name: k, type: p.type || 'http', behavior: p.behavior || 'domain', format: p.format || 'yaml', interval: p.interval || 86400, autoUrl: false, customUrl: '', path: p.path || '', file: '', payload: '' };

                    if (rp.type === 'http') {
                        rp.customUrl = p.url || '';
                        if (rp.customUrl.includes('meta-rules-dat')) {
                            rp.autoUrl = true;
                            const parts = rp.customUrl.split('/');
                            const filename = parts[parts.length-1];
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
                        proxies: g.proxies || [],
                        use: g.use || [],
                        filter: g.filter || '',
                        'exclude-filter': g['exclude-filter'] || '',
                        url: g.url || 'https://www.gstatic.com/generate_204',
                        interval: g.interval || 300,
                        tolerance: g.tolerance || 50,
                        timeout: g.timeout || 0,
                        lazy: g.lazy !== false,
                        'dialer-proxy': g['dialer-proxy'] || '',
                        strategy: g.strategy || 'consistent-hashing',
                        'include-all': g['include-all'] === true
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

        const copyYaml = async () => {
            try {
                await navigator.clipboard.writeText(fullYaml.value);
                alert('YAML 已成功复制到剪贴板！');
            } catch (e) {
                alert('复制失败，请在右侧代码框中手动全选复制。');
            }
        };

        const downloadYaml = () => {
            const blob = new Blob([fullYaml.value], { type: 'text/yaml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'config.yaml';
            a.click();
            URL.revokeObjectURL(url);
        };

        onMounted(() => {
            try {
                const saved = localStorage.getItem('mihomo_web_config_v17');
                if (saved) {
                    const p = JSON.parse(saved);
                    if (p.config) deepMerge(config.value, p.config);
                    if (p.uiState) {
                        deepMerge(uiState.value, p.uiState);
                        if (!Object.prototype.hasOwnProperty.call(p.uiState, 'tunDnsHijackEnabled')) {
                            uiState.value.tunDnsHijackEnabled = !!String(uiState.value.tunDnsHijack || '').trim();
                        }
                        if (!Object.prototype.hasOwnProperty.call(p.uiState, 'enableDnsFallback')) {
                            uiState.value.enableDnsFallback = !!String(uiState.value.dnsFallback || '').trim();
                        }
                    }
                    if (p.providersList) providersList.value = p.providersList;
                    if (p.ruleProvidersList) ruleProvidersList.value = p.ruleProvidersList;

                    if (config.value.proxies && Array.isArray(config.value.proxies)) {
                        config.value.proxies = config.value.proxies.map(px => parseSingleProxyNode(px)).filter(Boolean);
                    }
                } else {
                    injectRegionGroups();
                }
            } catch(e) {
                console.error("缓存数据解析失败，已跳过:", e);
                crashError.value = `应用启动崩溃: ${e.message}`;
            }

                uiState.value.nftablesConfig = normalizeNftablesConfig(uiState.value.nftablesConfig, config.value);
                sanitizeNftMarks();
                if (config.value && config.value.dns) config.value.dns.listen = String(getListenPort(config.value.dns.listen, 53));

            try {
                buildYaml();
            } catch (e) {
                console.error("初始 YAML 构建异常:", e);
            }
        });

        return {
            tabs, currentTab, yamlPreviewBox, fileInput, uiState, config, panels, providersList, ruleProvidersList,
            pickPanel, addListener, removeListener, addProvider, removeProvider, addRuleProvider, removeRuleProvider,
            getRuleProviderUrl, addManualProxy, addGroup, removeGroup, getAvailableGroupMembers, addRule, addCondition,
            draggedRuleIndex, onRuleDragStart, onRuleDragEnter, onRuleDrop, onRuleDragEnd, getInlinePayloadPreview,
            yamlSections, fullYaml, copyYaml, downloadYaml, clearLists, forceClearCache, triggerYamlImport,
            handleYamlImport, handleFocus, isLocating, renderStatus, injectRegionGroups, autoCategorizeProxies,
            handleTproxyToggle, handleTunToggle, cancelTproxyEnable, resolveTproxyConflicts, nftMarkIssues, sanitizeNftMarks, resetNftMarksSafe, routingCommands,
            copyCommands, nftablesScript, copyNftables, downloadNftables, systemdService, installScript,
            copyInstallScript, updateRuleProviderName, resetGeoUrls, formatConditions,
            dnsListenPort, dnsListenPortInput, normalizeDnsListenInput, showHostsEditor, usingTransparentProxy, dnsHijackEnabled, dnsForwardConflict, dnsLocalForwardNeedsNon53, dnsPathPreview, specifiedPortsContain53,
            crashError, askConfirm
        };
    }
}).mount('#app');

})(window);
