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

    if (!window.MihomoFeatureModules
        || !window.MihomoFeatureModules.createDnsModule
        || !window.MihomoFeatureModules.createTproxyModule
        || !window.MihomoFeatureModules.createRulesModule
        || !window.MihomoFeatureModules.createYamlModule
    ) {
        throw new Error('功能模块未加载，请确认先引入 ./mihomo.dns.js ./mihomo.tproxy.js ./mihomo.rules.js ./mihomo.yaml.js');
    }

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

        const dnsModule = window.MihomoFeatureModules.createDnsModule({
            ref, computed, watch, config, uiState
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
            watch, computed, config, uiState, dnsListenPort
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
                if (scrollBox) { scrollBox.scrollTo({ top: scrollBox.scrollHeight, behavior: 'smooth' }); }
            });
        };

        const addListener = () => { config.value.listeners.push({ name: `listener-${config.value.listeners.length + 1}`, type: 'mixed', port: 7890, listen: '::', udp: true }); };
        const removeListener = (idx) => { config.value.listeners.splice(idx, 1); };

        const rulesModule = window.MihomoFeatureModules.createRulesModule({
            ref, config, uiState, scrollToBottom
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

        const yamlModule = window.MihomoFeatureModules.createYamlModule({
            ref, config, uiState, providersList, ruleProvidersList, parseSingleProxyNode, getRuleProviderUrl
        });
        const {
            yamlSections,
            fullYaml,
            buildYaml
        } = yamlModule;
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
