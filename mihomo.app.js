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

    if (
        !window.MihomoFeatureModules ||
        !window.MihomoFeatureModules.createDnsModule ||
        !window.MihomoFeatureModules.createTproxyModule ||
        !window.MihomoFeatureModules.createRulesModule ||
        !window.MihomoFeatureModules.createYamlModule
    ) {
        throw new Error('功能模块未加载，请确认先引入 ./mihomo.dns.js ./mihomo.tproxy.js ./mihomo.rules.js ./mihomo.yaml.js');
    }

    const STORAGE_KEY = 'mihomo_web_config_v17';

    createApp({
        setup() {
            const crashError = ref(null);

            onErrorCaptured((err, instance, info) => {
                console.error('UI渲染层捕获到异常，已自动拦截以防止白屏:', err, info);
                crashError.value = `Error: ${err.message}\nInfo: ${info}\nStack: ${err.stack}`;
                return false;
            });

            const forceClearCache = () => {
                localStorage.removeItem(STORAGE_KEY);
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
                useMirrorForPanels: true,
                selectedPanel: '',
                useMirrorForGeo: true,
                useMirrorForRuleProviders: true,
                showInstallScript: false,
                showSystemdService: false,
                downloadFileName: 'config.yaml',
                tunDnsHijackEnabled: true,
                tunDnsHijack: "any:53\ntcp://any:53",
                tproxyEnable: false,
                showTproxyConflict: false,
                tproxyConflicts: [],
                pendingAction: '',
                nftablesConfig: {
                    nftTable: 'mihomo',
                    tproxyPort: 7894,
                    listen: '0.0.0.0',
                    udp: true,
                    tproxyIpv6: false,
                    ingressIface: '',
                    egressIface: '',
                    routeMarkHex: '112',
                    tproxyMarkHex: '111',
                    proxyUid: '',
                    proxyGid: '',
                    hijackDns: true,
                    privateIps: "0.0.0.0/8\n10.0.0.0/8\n100.64.0.0/10\n127.0.0.0/8\n169.254.0.0/16\n172.16.0.0/12\n192.0.0.0/24\n192.0.2.0/24\n192.88.99.0/24\n192.168.0.0/16\n198.51.100.0/24\n203.0.113.0/24\n224.0.0.0/4\n240.0.0.0/4",
                    privateIpsV6: "::/128\n::1/128\nfc00::/7\nfe80::/10\n2001:db8::/32\n64:ff9b::/96\n100::/64\nff00::/8",
                    bypassCnIp: false,
                    cnIps: '',
                    cnIpsV6: '',
                    filterPorts: false,
                    commonPorts: '22,587,465,995,993,143,80,443,853,9418'
                },
                snifferSniff: { HTTP: "80, 8080-8880", TLS: "443, 8443", QUIC: "443, 8443" },
                snifferSkipDomain: "Mijia Cloud\n*.apple.com",
                snifferForceDomain: "",
                snifferPortWhitelist: "",
                fakeIpFilter: "*.lan\n*.local\ntime.*.com\nntp.*.com\n*.msftconnecttest.com",
                hosts: "",
                dnsNameserverPolicy: "",
                useLocalDns53Forward: false,
                enableDnsFallback: false,
                dnsDefaultNameservers: "223.5.5.5\n119.29.29.29\n1.1.1.1\n8.8.8.8",
                dnsNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
                dnsFallback: "https://dns.google/dns-query\nhttps://cloudflare-dns.com/dns-query",
                dnsProxyServerNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
                dnsDirectNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
                fallbackFilterGeositeEnable: true,
                fallbackFilterGeosite: "gfw",
                fallbackFilterIpcidr: "240.0.0.0/4\n0.0.0.0/32",
                fallbackFilterDomain: "+.google.com\n+.facebook.com",
                rules: [
                    { type: 'GEOSITE', value: 'category-ads-all', target: 'REJECT', noResolve: false, not: false },
                    { type: 'GEOSITE', value: 'google', target: 'Proxy', noResolve: false, not: false },
                    { type: 'GEOIP', value: 'cn', target: 'DIRECT', noResolve: true, not: false },
                    { type: 'MATCH', value: '', target: 'Proxy', noResolve: false, not: false }
                ]
            });

            const getDefaultConfig = () => ({
                'mixed-port': 7890,
                port: 7891,
                'socks-port': 7892,
                'redir-port': 7893,
                'tproxy-port': 7894,
                listeners: [],
                'routing-mark': 112,
                'allow-lan': true,
                mode: 'rule',
                'log-level': 'info',
                ipv6: false,
                'global-client-fingerprint': '',
                'find-process-mode': 'strict',
                profile: { 'store-selected': true, 'store-fake-ip': true },
                'external-controller': '127.0.0.1:9090',
                secret: '',
                'external-ui': 'ui',
                'external-ui-url': '',
                'interface-name': '',
                'geodata-mode': true,
                'unified-delay': true,
                'tcp-concurrent': true,
                tun: {
                    enable: false,
                    stack: 'system',
                    device: '',
                    mtu: 1500,
                    gso: false,
                    'gso-max-size': 65536,
                    'auto-route': true,
                    'strict-route': true,
                    'auto-detect-interface': true,
                    'endpoint-independent-nat': false,
                    'dns-hijack': ['any:53', 'tcp://any:53']
                },
                sniffer: {
                    enable: false,
                    'force-dns-mapping': true,
                    'parse-pure-ip': true,
                    'override-destination': false
                },
                dns: {
                    enable: true,
                    listen: '53',
                    ipv6: false,
                    'enhanced-mode': 'redir-host',
                    'fake-ip-range': '198.18.0.1/16',
                    'fake-ip-filter-mode': 'blacklist',
                    'prefer-h3': false,
                    'respect-rules': false,
                    'use-hosts': false,
                    'use-system-hosts': false,
                    'direct-nameserver-follow-policy': false,
                    'fallback-filter': { geoip: true, 'geoip-code': 'CN' }
                },
                geo: {
                    'auto-update': true,
                    interval: 24,
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
                    config.value.geo.url = {
                        geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
                        geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
                        mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb'
                    };
                } else {
                    config.value.geo.url = {
                        geoip: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat',
                        geosite: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat',
                        mmdb: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/country.mmdb'
                    };
                }
            });

            const resetGeoUrls = () => {
                uiState.value.useMirrorForGeo = true;
                config.value.geo.url = {
                    geoip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
                    geosite: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
                    mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb'
                };
            };

            const dnsModule = window.MihomoFeatureModules.createDnsModule({
                ref,
                computed,
                watch,
                config,
                uiState
            });
            const {
                dnsListenPortInput,
                normalizeDnsListenInput,
                dnsListenPort,
                showHostsEditor,
                usingTransparentProxy,
                dnsHijackEnabled,
                dnsForwardConflict,
                dnsLocalForwardNeedsNon53,
                specifiedPortsContain53,
                dnsPathPreview
            } = dnsModule;

            const tproxyModule = window.MihomoFeatureModules.createTproxyModule({
                watch,
                computed,
                config,
                uiState,
                dnsListenPort
            });
            const {
                handleTproxyToggle,
                handleTunToggle,
                cancelTproxyEnable,
                resolveTproxyConflicts,
                nftMarkIssues,
                sanitizeNftMarks,
                resetNftMarksSafe,
                routingCommands,
                copyCommands,
                nftablesScript,
                copyNftables,
                downloadNftables,
                systemdService,
                installScript,
                copyInstallScript
            } = tproxyModule;

            const scrollToBottom = () => {
                nextTick(() => {
                    const scrollBox = document.getElementById('main-scroll');
                    if (scrollBox) {
                        scrollBox.scrollTo({ top: scrollBox.scrollHeight, behavior: 'smooth' });
                    }
                });
            };

            const addListener = () => {
                config.value.listeners.push({
                    name: `listener-${config.value.listeners.length + 1}`,
                    type: 'mixed',
                    port: 7890,
                    listen: '::',
                    udp: true
                });
            };
            const removeListener = (idx) => {
                config.value.listeners.splice(idx, 1);
            };

            const rulesModule = window.MihomoFeatureModules.createRulesModule({
                ref,
                config,
                uiState,
                scrollToBottom
            });
            const {
                formatConditions,
                addCondition,
                addRule,
                draggedRuleIndex,
                onRuleDragStart,
                onRuleDragEnter,
                onRuleDrop,
                onRuleDragEnd,
                parseRuleString
            } = rulesModule;

            const parseSingleProxyNode = (px) => {
                if (!px) return null;

                let portVal = px.port;
                if (typeof portVal === 'string' && !portVal.includes('-')) {
                    const num = Number(portVal);
                    if (!isNaN(num)) portVal = num;
                }

                const base = {
                    name: px.name || `Node-${Math.floor(Math.random() * 1000)}`,
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
                    smux: {
                        enabled: !!(px.smux && px.smux.enabled),
                        protocol: px.smux?.protocol || 'h2mux',
                        'max-connections': px.smux?.['max-connections'] || 4,
                        padding: !!(px.smux?.padding)
                    },
                    'ws-opts': {
                        path: px['ws-opts']?.path || '/',
                        headers: { Host: px['ws-opts']?.headers?.Host || '' },
                        'max-early-data': px['ws-opts']?.['max-early-data'] || 0,
                        'early-data-header-name': px['ws-opts']?.['early-data-header-name'] || 'Sec-WebSocket-Protocol'
                    },
                    'grpc-opts': { 'grpc-service-name': px['grpc-opts']?.['grpc-service-name'] || '' },
                    'httpupgrade-opts': { host: px['httpupgrade-opts']?.host || '', path: px['httpupgrade-opts']?.path || '/' },
                    'h2-opts': { host: px['h2-opts']?.host || '', path: px['h2-opts']?.path || '/' },
                    'http-opts': {
                        path: px['http-opts']?.path || '/',
                        host: px['http-opts']?.host || '',
                        headers: { Host: px['http-opts']?.headers?.Host || '' }
                    },
                    'xhttp-opts': {
                        path: px['xhttp-opts']?.path || '/',
                        host: px['xhttp-opts']?.host || '',
                        mode: px['xhttp-opts']?.mode || 'auto'
                    },
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
                    if (base['http-opts'].headers && base['http-opts'].headers.Host) {
                        base['http-opts'].host = Array.isArray(base['http-opts'].headers.Host)
                            ? base['http-opts'].headers.Host[0]
                            : base['http-opts'].headers.Host;
                    }
                }
                if (px.type === 'tuic' && !base.uuid) base.uuid = px.uuid || '';
                return base;
            };

            const addManualProxy = () => {
                config.value.proxies.push(parseSingleProxyNode({ type: 'vless' }));
                scrollToBottom();
            };

            const addGroup = () => {
                config.value['proxy-groups'].push({
                    name: `Group-${(config.value['proxy-groups'] || []).length + 1}`,
                    type: 'select',
                    proxies: [],
                    use: [],
                    filter: '',
                    'exclude-filter': '',
                    url: 'https://www.gstatic.com/generate_204',
                    interval: 300,
                    tolerance: 50,
                    timeout: 0,
                    lazy: false,
                    'dialer-proxy': '',
                    strategy: 'consistent-hashing',
                    'include-all': false,
                    _collapsed: true
                });
                scrollToBottom();
            };

            const removeGroup = (idx) => {
                config.value['proxy-groups'].splice(idx, 1);
            };

            const groupProxyDrag = ref({ groupName: '', fromIndex: -1 });

            const toggleGroupCollapse = (g) => {
                if (!g) return;
                g._collapsed = !g._collapsed;
            };

            const collapseAllGroups = () => {
                (config.value['proxy-groups'] || []).forEach((g) => {
                    if (g) g._collapsed = true;
                });
            };

            const expandAllGroups = () => {
                (config.value['proxy-groups'] || []).forEach((g) => {
                    if (g) g._collapsed = false;
                });
            };

            const ensureGroupCollapseState = (forceCollapse = false) => {
                const groups = config.value['proxy-groups'];
                if (!Array.isArray(groups)) return;

                groups.forEach((g) => {
                    if (!g || typeof g !== 'object') return;
                    if (forceCollapse) {
                        g._collapsed = true;
                    } else if (typeof g._collapsed !== 'boolean') {
                        g._collapsed = true;
                    }
                });
            };

            watch(
                [
                    () => config.value['proxy-groups'],
                    () => (config.value['proxy-groups'] || []).length
                ],
                () => {
                    ensureGroupCollapseState(false);
                },
                { immediate: true, flush: 'sync' }
            );

            const removeGroupProxyMember = (g, idx) => {
                if (!g || !Array.isArray(g.proxies)) return;
                g.proxies.splice(idx, 1);
            };

            const getOrderedAvailableGroupMembers = (g) => {
                const available = getAvailableGroupMembers(g && g.name);
                if (!g || !Array.isArray(g.proxies) || g.proxies.length === 0) return available;

                const availableMap = new Map(available.map((name) => [String(name || '').trim(), name]));
                const selected = [];
                const selectedSet = new Set();

                g.proxies.forEach((name) => {
                    const key = String(name || '').trim();
                    if (!key || selectedSet.has(key) || !availableMap.has(key)) return;
                    selectedSet.add(key);
                    selected.push(availableMap.get(key));
                });

                const rest = available.filter((name) => !selectedSet.has(String(name || '').trim()));
                return [...selected, ...rest];
            };

            const onInlineGroupMemberDragStart = (g, name, e) => {
                if (!g || g['include-all'] || !Array.isArray(g.proxies)) return;
                const idx = g.proxies.indexOf(name);
                if (idx < 0) return;

                if (e && e.currentTarget && e.currentTarget.classList) {
                    e.currentTarget.classList.add('dragging');
                }

                onGroupProxyDragStart(g, idx, e);
            };

            const onInlineGroupMemberDragOver = (g, name, e) => {
                if (!g || g['include-all'] || !Array.isArray(g.proxies)) return;
                if (!g.proxies.includes(name)) return;

                if (e && e.dataTransfer) {
                    e.dataTransfer.dropEffect = 'move';
                }
            };

            const onInlineGroupMemberDrop = (g, name, e) => {
                if (!g || g['include-all'] || !Array.isArray(g.proxies)) {
                    onGroupProxyDragEnd();
                    return;
                }

                const idx = g.proxies.indexOf(name);
                if (idx < 0) {
                    onGroupProxyDragEnd();
                    return;
                }

                onGroupProxyDrop(g, idx);

                if (e && e.currentTarget && e.currentTarget.classList) {
                    e.currentTarget.classList.remove('dragging');
                }
            };

            const onGroupProxyDragStart = (g, idx, e) => {
                if (!g || !Array.isArray(g.proxies)) return;
                groupProxyDrag.value = { groupName: g.name, fromIndex: idx };
                if (e && e.dataTransfer) {
                    e.dataTransfer.effectAllowed = 'move';
                    try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
                }
            };

            const onGroupProxyDrop = (g, idx) => {
                if (!g || !Array.isArray(g.proxies)) return;
                const drag = groupProxyDrag.value;
                if (!drag || drag.groupName !== g.name) return;

                const from = drag.fromIndex;
                const to = idx;
                if (from < 0 || to < 0 || from === to) {
                    onGroupProxyDragEnd();
                    return;
                }

                const moved = g.proxies.splice(from, 1)[0];
                if (moved === undefined) {
                    onGroupProxyDragEnd();
                    return;
                }

                g.proxies.splice(to, 0, moved);
                onGroupProxyDragEnd();
            };

            const onGroupProxyDragEnd = () => {
                groupProxyDrag.value = { groupName: '', fromIndex: -1 };
                document.querySelectorAll('[data-group-member-draggable="1"].dragging').forEach((el) => el.classList.remove('dragging'));
            };

            const groupUseDrag = ref({ groupName: '', fromIndex: -1 });

            const onGroupUseDragStart = (g, name, e) => {
                if (!g || g['include-all'] || !Array.isArray(g.use)) return;
                const idx = g.use.indexOf(name);
                if (idx < 0) return;

                groupUseDrag.value = { groupName: g.name, fromIndex: idx };

                if (e && e.dataTransfer) {
                    e.dataTransfer.effectAllowed = 'move';
                    try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
                }
            };

            const onGroupUseDragOver = (g, name, e) => {
                if (!g || g['include-all'] || !Array.isArray(g.use)) return;
                if (!g.use.includes(name)) return;

                if (e && e.dataTransfer) {
                    e.dataTransfer.dropEffect = 'move';
                }
            };

            const onGroupUseDrop = (g, name) => {
                if (!g || g['include-all'] || !Array.isArray(g.use)) {
                    onGroupUseDragEnd();
                    return;
                }

                const drag = groupUseDrag.value;
                if (!drag || drag.groupName !== g.name) return;

                const from = drag.fromIndex;
                const to = g.use.indexOf(name);

                if (from < 0 || to < 0 || from === to) {
                    onGroupUseDragEnd();
                    return;
                }

                const moved = g.use.splice(from, 1)[0];
                if (moved === undefined) {
                    onGroupUseDragEnd();
                    return;
                }

                g.use.splice(to, 0, moved);
                onGroupUseDragEnd();
            };

            const onGroupUseDragEnd = () => {
                groupUseDrag.value = { groupName: '', fromIndex: -1 };
                document.querySelectorAll('[data-group-use-draggable="1"].dragging').forEach((el) => el.classList.remove('dragging'));
            };

            const proxyGroupDrag = ref({ fromIndex: -1, overIndex: -1 });

            const onProxyGroupDragStart = (idx, e) => {
                const groups = config.value['proxy-groups'] || [];
                if (idx < 0 || idx >= groups.length) return;

                proxyGroupDrag.value = { fromIndex: idx, overIndex: idx };

                if (e && e.dataTransfer) {
                    e.dataTransfer.effectAllowed = 'move';
                    try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
                }
            };

            const onProxyGroupDragOver = (idx) => {
                if (proxyGroupDrag.value.fromIndex < 0) return;
                proxyGroupDrag.value.overIndex = idx;
            };

            const onProxyGroupDrop = (idx) => {
                const groups = config.value['proxy-groups'];
                if (!Array.isArray(groups)) return;

                const from = proxyGroupDrag.value.fromIndex;
                const to = idx;

                if (from < 0 || to < 0 || from === to || from >= groups.length || to >= groups.length) {
                    onProxyGroupDragEnd();
                    return;
                }

                const moved = groups.splice(from, 1)[0];
                if (moved === undefined) {
                    onProxyGroupDragEnd();
                    return;
                }

                groups.splice(to, 0, moved);
                onProxyGroupDragEnd();
            };

            const onProxyGroupDragEnd = () => {
                proxyGroupDrag.value = { fromIndex: -1, overIndex: -1 };
            };

            const getValidStaticGroupMemberNames = (currentGroupName = '') => {
                const names = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE']);

                (config.value.proxies || []).forEach((p) => {
                    const name = String(p?.name || '').trim();
                    if (name) names.add(name);
                });

                (config.value['proxy-groups'] || []).forEach((group) => {
                    const name = String(group?.name || '').trim();
                    if (name && name !== currentGroupName) names.add(name);
                });

                return names;
            };

            const pruneInvalidGroupProxyMembers = () => {
                const groups = config.value['proxy-groups'];
                if (!Array.isArray(groups)) return;

                groups.forEach((g) => {
                    if (!Array.isArray(g.proxies)) {
                        g.proxies = [];
                        return;
                    }

                    const validNames = getValidStaticGroupMemberNames(g.name);
                    const next = g.proxies.filter((name) => validNames.has(String(name || '').trim()));

                    if (next.length !== g.proxies.length) {
                        g.proxies = next;
                    }
                });
            };

            watch(
                [
                    () => config.value.proxies,
                    () => config.value['proxy-groups'],
                    () => (config.value.proxies || []).length,
                    () => (config.value['proxy-groups'] || []).length
                ],
                () => {
                    pruneInvalidGroupProxyMembers();
                },
                { immediate: true, flush: 'sync' }
            );

            const getAvailableGroupMembers = (currentGroupName) => {
                let groups = (config.value['proxy-groups'] || []).map(g => g.name);
                if (currentGroupName) groups = groups.filter(n => n !== currentGroupName);
                return ['DIRECT', 'REJECT', ...groups, ...(config.value.proxies || []).map(p => p.name)];
            };

            const getOrderedGroupUseProviders = (g) => {
                const available = (providersList.value || []).map((p) => p && p.name).filter(Boolean);
                if (!g || !Array.isArray(g.use) || g.use.length === 0) return available;

                const availableMap = new Map(available.map((name) => [String(name || '').trim(), name]));
                const selected = [];
                const selectedSet = new Set();

                g.use.forEach((name) => {
                    const key = String(name || '').trim();
                    if (!key || selectedSet.has(key) || !availableMap.has(key)) return;
                    selectedSet.add(key);
                    selected.push(availableMap.get(key));
                });

                const rest = available.filter((name) => !selectedSet.has(String(name || '').trim()));
                return [...selected, ...rest];
            };

            const pruneInvalidGroupUseMembers = () => {
                const groups = config.value['proxy-groups'];
                if (!Array.isArray(groups)) return;

                const validProviders = new Set(
                    (providersList.value || [])
                        .map((p) => String((p && p.name) || '').trim())
                        .filter(Boolean)
                );

                groups.forEach((g) => {
                    if (!Array.isArray(g.use)) {
                        g.use = [];
                        return;
                    }

                    const next = g.use.filter((name) => validProviders.has(String(name || '').trim()));
                    if (next.length !== g.use.length) {
                        g.use = next;
                    }
                });
            };

            watch(
                [
                    () => providersList.value,
                    () => config.value['proxy-groups'],
                    () => (providersList.value || []).length,
                    () => (config.value['proxy-groups'] || []).length
                ],
                () => {
                    pruneInvalidGroupUseMembers();
                },
                { immediate: true, flush: 'sync' }
            );

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
                    mainGroup = {
                        name: 'Proxy',
                        type: 'select',
                        proxies: ['自动选择', 'DIRECT'],
                        use: [],
                        filter: '',
                        'exclude-filter': '',
                        url: 'https://www.gstatic.com/generate_204',
                        interval: 300,
                        tolerance: 50,
                        timeout: 0,
                        lazy: false,
                        'dialer-proxy': '',
                        strategy: 'consistent-hashing',
                        'include-all': false
                    };
                    config.value['proxy-groups'].unshift(mainGroup);
                }
                let autoGroup = config.value['proxy-groups'].find(g => g.name === '自动选择');
                if (!autoGroup) {
                    autoGroup = {
                        name: '自动选择',
                        type: 'url-test',
                        proxies: [],
                        use: (providersList.value || []).map(p => p.name),
                        filter: '',
                        'exclude-filter': '',
                        url: 'https://www.gstatic.com/generate_204',
                        interval: 300,
                        tolerance: 50,
                        timeout: 0,
                        lazy: true,
                        'dialer-proxy': '',
                        strategy: 'consistent-hashing',
                        'include-all': false
                    };
                    config.value['proxy-groups'].splice(1, 0, autoGroup);
                }

                regions.forEach(r => {
                    if (!config.value['proxy-groups'].find(g => g.name === r.name)) {
                        config.value['proxy-groups'].push({
                            name: r.name,
                            type: 'url-test',
                            proxies: [],
                            use: (providersList.value || []).map(p => p.name),
                            filter: r.filter,
                            'exclude-filter': '',
                            url: 'https://www.gstatic.com/generate_204',
                            interval: 300,
                            tolerance: 50,
                            timeout: 0,
                            lazy: true,
                            'dialer-proxy': '',
                            strategy: 'consistent-hashing',
                            'include-all': false
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
                            if (jsPattern.startsWith('(?i)')) {
                                jsPattern = jsPattern.substring(4);
                                flags = 'i';
                            }
                            const regex = new RegExp(jsPattern, flags);

                            const matched = config.value.proxies
                                .filter(px => regex.test(px.name))
                                .map(px => px.name);

                            matched.forEach(name => {
                                if (!g.proxies) g.proxies = [];
                                if (!g.proxies.includes(name)) g.proxies.push(name);
                            });

                            (providersList.value || []).forEach(prov => {
                                if (!g.use) g.use = [];
                                if (prov.name && !g.use.includes(prov.name)) g.use.push(prov.name);
                            });
                        } catch (e) {}
                    }
                });
            };

            const pickPanel = (p) => {
                uiState.value.selectedPanel = p.id;
                config.value['external-ui-url'] = uiState.value.useMirrorForPanels ? p.mirrorUrl : p.rawUrl;
            };

            const addProvider = () => {
                providersList.value.push({
                    name: `Provider-${(providersList.value || []).length + 1}`,
                    type: 'http',
                    url: '',
                    interval: 3600,
                    healthUrl: 'https://www.gstatic.com/generate_204',
                    overrideDialerProxy: '',
                    useDownloadProxy: false,
                    downloadProxy: '',
                    inlineProxies: [],
                    lazy: true,
                    healthCheckLazy: true,
                    healthCheckTimeout: 5000
                });
                scrollToBottom();
            };

            const removeProvider = (idx) => providersList.value.splice(idx, 1);

            const addRuleProvider = () => {
                ruleProvidersList.value.push({
                    name: '',
                    type: 'http',
                    file: '',
                    behavior: 'domain',
                    format: 'yaml',
                    interval: 86400,
                    autoUrl: true,
                    customUrl: '',
                    path: '',
                    payload: '',
                    _collapsed: false
                });
                scrollToBottom();
            };

            const removeRuleProvider = (idx) => ruleProvidersList.value.splice(idx, 1);

            const ruleProviderDrag = ref({ fromIndex: -1, overIndex: -1 });

            const toggleRuleProviderCollapse = (rp) => {
                if (!rp) return;
                rp._collapsed = !rp._collapsed;
            };

            const collapseAllRuleProviders = () => {
                (ruleProvidersList.value || []).forEach((rp) => {
                    if (rp) rp._collapsed = true;
                });
            };

            const expandAllRuleProviders = () => {
                (ruleProvidersList.value || []).forEach((rp) => {
                    if (rp) rp._collapsed = false;
                });
            };

            const ensureRuleProviderCollapseState = () => {
                const list = ruleProvidersList.value;
                if (!Array.isArray(list)) return;

                list.forEach((rp) => {
                    if (!rp || typeof rp !== 'object') return;
                    if (typeof rp._collapsed !== 'boolean') {
                        rp._collapsed = false;
                    }
                });
            };

            watch(
                [
                    () => ruleProvidersList.value,
                    () => (ruleProvidersList.value || []).length
                ],
                () => {
                    ensureRuleProviderCollapseState();
                },
                { immediate: true, flush: 'sync' }
            );

            const onRuleProviderDragStart = (idx, e) => {
                const list = ruleProvidersList.value || [];
                if (idx < 0 || idx >= list.length) return;

                ruleProviderDrag.value = { fromIndex: idx, overIndex: idx };

                if (e && e.dataTransfer) {
                    e.dataTransfer.effectAllowed = 'move';
                    try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
                }
            };

            const onRuleProviderDragOver = (idx) => {
                if (ruleProviderDrag.value.fromIndex < 0) return;
                ruleProviderDrag.value.overIndex = idx;
            };

            const onRuleProviderDrop = (idx) => {
                const list = ruleProvidersList.value;
                if (!Array.isArray(list)) return;

                const from = ruleProviderDrag.value.fromIndex;
                const to = idx;

                if (from < 0 || to < 0 || from === to || from >= list.length || to >= list.length) {
                    onRuleProviderDragEnd();
                    return;
                }

                const moved = list.splice(from, 1)[0];
                if (moved === undefined) {
                    onRuleProviderDragEnd();
                    return;
                }

                list.splice(to, 0, moved);
                onRuleProviderDragEnd();
            };

            const onRuleProviderDragEnd = () => {
                ruleProviderDrag.value = { fromIndex: -1, overIndex: -1 };
            };

            const hasDuplicateRuleProviderName = (name, currentItem = null) => {
                const target = String(name || '').trim();
                if (!target) return false;

                return (ruleProvidersList.value || []).some((item) => {
                    if (!item || item === currentItem) return false;
                    return String(item.name || '').trim() === target;
                });
            };

            const updateRuleProviderName = (rp, newName, e = null) => {
                if (!rp || typeof rp !== 'object') return;

                const oldName = String(rp.name || '');
                const nextName = String(newName ?? '');
                const trimmedNext = nextName.trim();

                if (trimmedNext && hasDuplicateRuleProviderName(trimmedNext, rp)) {
                    window.alert(`规则集合名称重复：${trimmedNext}`);
                    if (e && e.target) e.target.value = oldName;
                    return;
                }

                rp.name = nextName;
                if (oldName && oldName !== nextName) {
                    (uiState.value.rules || []).forEach(r => {
                        if (r.type === 'RULE-SET' && r.value === oldName) r.value = nextName;
                        if (r.logic && r.conditions) {
                            r.conditions.forEach(cond => {
                                if (cond.type === 'RULE-SET' && cond.value === oldName) cond.value = nextName;
                            });
                        }
                    });
                }
            };

            const providerNameSnapshots = new WeakMap();
            const proxyNameSnapshots = new WeakMap();
            const groupNameSnapshots = new WeakMap();

            const ensureRenameSnapshots = () => {
                (providersList.value || []).forEach((p) => {
                    if (p && typeof p === 'object' && !providerNameSnapshots.has(p)) {
                        providerNameSnapshots.set(p, String(p.name || ''));
                    }
                });

                (config.value.proxies || []).forEach((px) => {
                    if (px && typeof px === 'object' && !proxyNameSnapshots.has(px)) {
                        proxyNameSnapshots.set(px, String(px.name || ''));
                    }
                });

                (config.value['proxy-groups'] || []).forEach((g) => {
                    if (g && typeof g === 'object' && !groupNameSnapshots.has(g)) {
                        groupNameSnapshots.set(g, String(g.name || ''));
                    }
                });
            };

            watch(
                [
                    () => providersList.value,
                    () => config.value.proxies,
                    () => config.value['proxy-groups'],
                    () => (providersList.value || []).length,
                    () => (config.value.proxies || []).length,
                    () => (config.value['proxy-groups'] || []).length
                ],
                () => {
                    ensureRenameSnapshots();
                },
                { immediate: true, flush: 'sync' }
            );

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

            const replaceProviderDialerRefs = (oldName, newName) => {
                (providersList.value || []).forEach((p) => {
                    if (!p || typeof p !== 'object') return;
                    if (p.downloadProxy === oldName) p.downloadProxy = newName;
                    if (p.overrideDialerProxy === oldName) p.overrideDialerProxy = newName;
                });
            };

            const replaceProviderInlineProxyRefs = (oldName, newName) => {
                (providersList.value || []).forEach((p) => {
                    if (!p || typeof p !== 'object') return;
                    replaceNameInList(p.inlineProxies, oldName, newName);
                });
            };

            const replaceRuleTargets = (oldName, newName) => {
                (uiState.value.rules || []).forEach((r) => {
                    if (r && r.target === oldName) r.target = newName;
                });
            };

            const updateProviderName = (p, newName) => {
                if (!p || typeof p !== 'object') return;
                const oldName = providerNameSnapshots.has(p) ? providerNameSnapshots.get(p) : String(p.name || '');
                p.name = newName;

                if (oldName === newName) return;

                (config.value['proxy-groups'] || []).forEach((g) => {
                    replaceNameInList(g.use, oldName, newName);
                });

                providerNameSnapshots.set(p, String(newName || ''));
            };

            const updateProxyName = (px, newName) => {
                if (!px || typeof px !== 'object') return;
                const oldName = proxyNameSnapshots.has(px) ? proxyNameSnapshots.get(px) : String(px.name || '');
                px.name = newName;

                if (oldName === newName) return;

                (config.value['proxy-groups'] || []).forEach((g) => {
                    replaceNameInList(g.proxies, oldName, newName);
                    replaceDialerProxyName(g, oldName, newName);
                });

                replaceProviderDialerRefs(oldName, newName);
                replaceProviderInlineProxyRefs(oldName, newName);

                (config.value.proxies || []).forEach((item) => {
                    if (item !== px) replaceDialerProxyName(item, oldName, newName);
                });

                replaceRuleTargets(oldName, newName);
                proxyNameSnapshots.set(px, String(newName || ''));
            };

            const updateGroupName = (g, newName) => {
                if (!g || typeof g !== 'object') return;
                const oldName = groupNameSnapshots.has(g) ? groupNameSnapshots.get(g) : String(g.name || '');
                g.name = newName;

                if (oldName === newName) return;

                (config.value['proxy-groups'] || []).forEach((item) => {
                    replaceNameInList(item.proxies, oldName, newName);
                    replaceDialerProxyName(item, oldName, newName);
                });

                replaceProviderDialerRefs(oldName, newName);

                (config.value.proxies || []).forEach((px) => {
                    replaceDialerProxyName(px, oldName, newName);
                });

                replaceRuleTargets(oldName, newName);

                if (Array.isArray(g.proxies)) {
                    g.proxies = g.proxies.filter((name) => String(name || '').trim() !== String(g.name || '').trim());
                }
                if (g['dialer-proxy'] === g.name) {
                    g['dialer-proxy'] = '';
                }

                groupNameSnapshots.set(g, String(newName || ''));
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
                if (askConfirm('确定要清空所有的节点、订阅和规则列表吗？')) {
                    config.value.proxies = [];
                    config.value['proxy-groups'] = [];
                    providersList.value = [];
                    ruleProvidersList.value = [];
                    uiState.value.rules = [];
                }
            };

            const getInlinePayloadPreview = (inlineProxies) => {
                if (!inlineProxies || inlineProxies.length === 0) return '[]';
                const nodes = inlineProxies.map(name => {
                    const px = (config.value.proxies || []).find(x => x.name === name);
                    if (!px) return null;
                    const cleanPx = JSON.parse(JSON.stringify(parseSingleProxyNode(px)));
                    return cleanPx;
                }).filter(Boolean);
                try {
                    return jsyaml.dump(nodes, { indent: 2, lineWidth: -1, sortKeys: false });
                } catch (e) {
                    return '# Preview Error';
                }
            };

            const yamlModule = window.MihomoFeatureModules.createYamlModule({
                ref,
                config,
                uiState,
                providersList,
                ruleProvidersList,
                parseSingleProxyNode,
                getRuleProviderUrl
            });
            const {
                yamlSections,
                fullYaml,
                buildYaml
            } = yamlModule;

            const safeBuildYaml = (reason = '') => {
                try {
                    buildYaml();
                    crashError.value = null;
                    if (!isLocating.value) renderStatus.value = '实时渲染';
                    return true;
                } catch (e) {
                    console.error('YAML 构建异常:', reason, e);
                    crashError.value = `YAML 构建异常: ${e.message}\nReason: ${reason}\nStack: ${e.stack || ''}`;
                    renderStatus.value = '渲染失败';
                    return false;
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
                if (!yamlPreviewBox.value) return;
                clearTimeout(scrollTimeout);
                isLocating.value = true;
                renderStatus.value = `追踪: ${keyword.trim().slice(0, 15)}...`;

                scrollTimeout = setTimeout(() => {
                    const container = yamlPreviewBox.value;
                    const lines = fullYaml.value.split('\n');
                    const idx = lines.findIndex(l => l.includes(keyword));
                    if (idx !== -1) {
                        const pre = container.querySelector('pre');
                        if (pre) {
                            const scrollHeight = pre.getBoundingClientRect().height;
                            const lineHeight = lines.length > 0 ? (scrollHeight / lines.length) : 0;
                            const targetY = Math.max(0, idx * lineHeight - 60);
                            container.scrollTo({ top: targetY, behavior: 'smooth' });
                        }
                    }
                    setTimeout(() => {
                        isLocating.value = false;
                        renderStatus.value = '实时渲染';
                    }, 1000);
                }, 100);
            };

            watch(currentTab, (newTab) => {
                if (!yamlPreviewBox.value) return;
                lastTarget = '';
                nextTick(() => {
                    setTimeout(() => {
                        const el = document.getElementById('yaml-' + newTab);
                        if (el) {
                            const container = yamlPreviewBox.value;
                            const pre = container.querySelector('pre');
                            if (!pre) return;
                            const topPos = el.offsetTop - pre.offsetTop;
                            container.scrollTo({ top: Math.max(0, topPos - 15), behavior: 'smooth' });
                        }
                    }, 50);
                });
            });

            let buildTimeout;
            watch([config, uiState, providersList, ruleProvidersList], () => {
                clearTimeout(buildTimeout);
                if (!isLocating.value) renderStatus.value = '实时渲染中...';

                buildTimeout = setTimeout(() => {
                    const ok = safeBuildYaml('state watcher');
                    if (!ok) return;

                    const sanitizedUiState = getSanitizedUiStateForSave(uiState.value, config.value);
                    localStorage.setItem(STORAGE_KEY, JSON.stringify({
                        config: config.value,
                        uiState: sanitizedUiState,
                        providersList: providersList.value,
                        ruleProvidersList: ruleProvidersList.value
                    }));
                }, 150);
            }, { deep: true });

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
                        const policy = {};
                        ensureStringArray(data.dns['nameserver-policy']).forEach((line) => {
                            const [key, val] = splitConfigLine(line);
                            if (key && val) policy[key] = val;
                        });
                        data.dns['nameserver-policy'] = policy;
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
                        uiState.value.dnsNameserverPolicy = Object.keys(data.dns['nameserver-policy'])
                            .map(k => `${k}: ${data.dns['nameserver-policy'][k]}`)
                            .join('\n');
                    } else {
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

            onMounted(() => {
                try {
                    const saved = localStorage.getItem(STORAGE_KEY);
                    if (saved) {
                        const p = JSON.parse(saved);
                        if (p.config) deepMerge(config.value, normalizeImportedConfigData(p.config));
                        if (p.uiState) {
                            deepMerge(uiState.value, p.uiState);
                            if (!Object.prototype.hasOwnProperty.call(p.uiState, 'tunDnsHijackEnabled')) {
                                uiState.value.tunDnsHijackEnabled = !!String(uiState.value.tunDnsHijack || '').trim();
                            }
                            if (!Object.prototype.hasOwnProperty.call(p.uiState, 'enableDnsFallback')) {
                                uiState.value.enableDnsFallback = !!String(uiState.value.dnsFallback || '').trim();
                            }
                        }
                        if (p.providersList) providersList.value = ensureArray(p.providersList).filter(isPlainObject);
                        if (p.ruleProvidersList) ruleProvidersList.value = ensureArray(p.ruleProvidersList).filter(isPlainObject);

                        if (config.value.proxies && Array.isArray(config.value.proxies)) {
                            config.value.proxies = config.value.proxies.map(px => parseSingleProxyNode(px)).filter(Boolean);
                        }
                    } else {
                        injectRegionGroups();
                    }
                } catch (e) {
                    console.error("缓存数据解析失败，已跳过:", e);
                    crashError.value = `应用启动崩溃: ${e.message}`;
                }

                ensureGroupCollapseState();
                ensureRuleProviderCollapseState();

                uiState.value.nftablesConfig = normalizeNftablesConfig(uiState.value.nftablesConfig, config.value);
                sanitizeNftMarks();
                if (config.value && config.value.dns) config.value.dns.listen = String(getListenPort(config.value.dns.listen, 53));

                safeBuildYaml('initial mount');
            });

            return {
                tabs,
                currentTab,
                yamlPreviewBox,
                fileInput,
                uiState,
                config,
                panels,
                providersList,
                ruleProvidersList,
                pickPanel,
                addListener,
                removeListener,
                addProvider,
                removeProvider,
                addRuleProvider,
                removeRuleProvider,
                toggleRuleProviderCollapse,
                collapseAllRuleProviders,
                expandAllRuleProviders,
                onRuleProviderDragStart,
                onRuleProviderDragOver,
                onRuleProviderDrop,
                onRuleProviderDragEnd,
                ruleProviderDrag,
                updateProviderName,
                getRuleProviderUrl,
                addManualProxy,
                addGroup,
                removeGroup,
                updateProxyName,
                updateGroupName,
                toggleGroupCollapse,
                collapseAllGroups,
                expandAllGroups,
                getAvailableGroupMembers,
                getOrderedAvailableGroupMembers,
                getOrderedGroupUseProviders,
                removeGroupProxyMember,
                onGroupProxyDragStart,
                onGroupProxyDrop,
                onGroupProxyDragEnd,
                groupProxyDrag,
                onInlineGroupMemberDragStart,
                onInlineGroupMemberDragOver,
                onInlineGroupMemberDrop,
                groupUseDrag,
                onGroupUseDragStart,
                onGroupUseDragOver,
                onGroupUseDrop,
                onGroupUseDragEnd,
                onProxyGroupDragStart,
                onProxyGroupDragOver,
                onProxyGroupDrop,
                onProxyGroupDragEnd,
                proxyGroupDrag,
                addRule,
                addCondition,
                draggedRuleIndex,
                onRuleDragStart,
                onRuleDragEnter,
                onRuleDrop,
                onRuleDragEnd,
                getInlinePayloadPreview,
                yamlSections,
                fullYaml,
                copyYaml,
                downloadYaml,
                downloadYamlWithRename,
                clearLists,
                forceClearCache,
                triggerYamlImport,
                handleYamlImport,
                handleFocus,
                isLocating,
                renderStatus,
                injectRegionGroups,
                autoCategorizeProxies,
                handleTproxyToggle,
                handleTunToggle,
                cancelTproxyEnable,
                resolveTproxyConflicts,
                nftMarkIssues,
                sanitizeNftMarks,
                resetNftMarksSafe,
                routingCommands,
                copyCommands,
                nftablesScript,
                copyNftables,
                downloadNftables,
                systemdService,
                installScript,
                copyInstallScript,
                updateRuleProviderName,
                resetGeoUrls,
                formatConditions,
                dnsListenPort,
                dnsListenPortInput,
                normalizeDnsListenInput,
                showHostsEditor,
                usingTransparentProxy,
                dnsHijackEnabled,
                dnsForwardConflict,
                dnsLocalForwardNeedsNon53,
                dnsPathPreview,
                specifiedPortsContain53,
                crashError,
                askConfirm
            };
        }
    }).mount('#app');

})(window);