(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createStateModule = function () {
        const tabs = [
            { id: 'general', name: '系统管控', icon: 'fas fa-sliders-h' },
            { id: 'network', name: '网络解析', icon: 'fas fa-network-wired' },
            { id: 'providers', name: '订阅/节点', icon: 'fas fa-link' },
            { id: 'groups', name: '策略分流', icon: 'fas fa-layer-group' },
            { id: 'rule-providers', name: '规则集', icon: 'fas fa-book-open' },
            { id: 'rules', name: '路由规则', icon: 'fas fa-route' },
            { id: 'tproxy', name: 'Tproxy代理', icon: 'fas fa-project-diagram' }
        ];

        const panels = [
            { id: 'zashboard', name: 'Zashboard', icon: 'fas fa-tachometer-alt', rawUrl: 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip', mirrorUrl: 'https://fastly.jsdelivr.net/gh/Zephyruso/zashboard@gh-pages/dist-cdn-fonts.zip' },
            { id: 'metacubexd', name: 'MetaCubeX-D', icon: 'fas fa-cube', rawUrl: 'https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip', mirrorUrl: 'https://fastly.jsdelivr.net/gh/MetaCubeX/metacubexd@gh-pages/metacubexd-gh-pages.zip' },
            { id: 'yacd-meta', name: 'Yacd-meta', icon: 'fas fa-chart-bar', rawUrl: 'https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip', mirrorUrl: 'https://fastly.jsdelivr.net/gh/MetaCubeX/Yacd-meta@gh-pages/Yacd-meta-gh-pages.zip' },
            { id: 'custom', name: '自定义', icon: 'fas fa-link', rawUrl: '', mirrorUrl: '' }
        ];

        const getDefaultUiState = () => ({
            useMirrorForPanels: true,
            selectedPanel: '',
            useMirrorForGeo: true,
            useMirrorForRuleProviders: true,
            showInstallScript: false,
            showSystemdService: false,
            downloadFileName: 'config.yaml',
            tunDnsHijackEnabled: true,
            tunDnsHijack: "any:53\ntcp://any:53",
            tunRouteAddressSet: "",
            tunRouteExcludeAddressSet: "",
            tunRouteAddress: "",
            tunRouteExcludeAddress: "",
            tunIncludeInterface: "",
            tunExcludeInterface: "",
            tunIncludeUid: "",
            tunIncludeUidRange: "",
            tunExcludeUid: "",
            tunExcludeUidRange: "",
            tunIncludeAndroidUser: "",
            tunIncludePackage: "",
            tunExcludePackage: "",
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
            snifferSniffOverrideDestination: { HTTP: false, TLS: false, QUIC: false },
            snifferSkipDomain: "Mijia Cloud\n*.apple.com",
            snifferForceDomain: "",
            snifferPortWhitelist: "",
            snifferSkipSrcAddress: "",
            snifferSkipDstAddress: "",
            fakeIpFilter: "*.lan\n*.local\ntime.*.com\nntp.*.com\n*.msftconnecttest.com",
            hosts: "",
            enableNameserverPolicy: false,
            dnsNameserverPolicy: "",
            enableProxyServerNameserverPolicy: false,
            dnsProxyServerNameserverPolicy: "",
            useLocalDns53Forward: false,
            enableDnsFallback: true,
            dnsDefaultNameservers: "223.5.5.5\n119.29.29.29\n1.1.1.1\n8.8.8.8",
            dnsNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
            dnsFallback: "https://dns.google/dns-query\nhttps://cloudflare-dns.com/dns-query",
            dnsProxyServerNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
            dnsDirectNameservers: "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
            fallbackFilterGeositeEnable: true,
            fallbackFilterGeosite: "gfw",
            fallbackFilterIpcidr: "240.0.0.0/4\n0.0.0.0/32",
            fallbackFilterDomain: "+.google.com\n+.facebook.com",
            generalLanAllowedIps: "",
            generalLanDisallowedIps: "",
            generalAuthentication: "",
            generalSkipAuthPrefixes: "",
            externalControllerCorsText: "",
            tlsConfigText: "",
            subRulesYaml: "",
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
            'bind-address': '',
            mode: 'rule',
            'log-level': 'info',
            ipv6: false,
            'global-client-fingerprint': '',
            'keep-alive-interval': '',
            'keep-alive-idle': '',
            'disable-keep-alive': false,
            'find-process-mode': 'strict',
            profile: { 'store-selected': true, 'store-fake-ip': true },
            'external-controller': '127.0.0.1:9090',
            'external-controller-cors': {},
            'external-controller-unix': '',
            'external-controller-pipe': '',
            'external-controller-tls': '',
            secret: '',
            'external-ui': 'ui',
            'external-ui-name': '',
            'external-ui-url': '',
            'interface-name': '',
            'geodata-mode': true,
            'geodata-loader': 'memconservative',
            'unified-delay': true,
            'tcp-concurrent': true,
            tls: {},
            'global-ua': '',
            'etag-support': true,
            experimental: {
                'quic-go-disable-gso': false,
                'quic-go-disable-ecn': false,
                'dialer-ip4p-convert': false
            },
            tun: {
                enable: false,
                stack: 'system',
                device: '',
                mtu: 1500,
                gso: false,
                'gso-max-size': 65536,
                'auto-route': true,
                'auto-redirect': false,
                'strict-route': true,
                'auto-detect-interface': true,
                'udp-timeout': 300,
                'iproute2-table-index': 2022,
                'iproute2-rule-index': 9000,
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
                'cache-algorithm': 'lru',
                listen: '53',
                ipv6: false,
                'enhanced-mode': 'redir-host',
                'fake-ip-range': '198.18.0.1/16',
                'fake-ip-range6': '',
                'fake-ip-filter-mode': 'blacklist',
                'fake-ip-ttl': '',
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
                    mmdb: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb',
                    asn: 'https://fastly.jsdelivr.net/gh/xishang0128/geoip@release/GeoLite2-ASN.mmdb'
                }
            },
            proxies: [],
            'proxy-groups': [
                { name: 'Proxy', type: 'select', proxies: ['自动选择', '香港节点', '台湾节点', '韩国节点', '日本节点', '新加坡节点', '美国节点', '其他国家', 'DIRECT'], use: [], filter: '', 'exclude-filter': '', 'exclude-type': '', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, timeout: 0, lazy: false, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '自动选择', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '香港节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)港|hk|hongkong|hong kong', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '台湾节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)台|tw|taiwan', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '韩国节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)韩|kr|korea|south korea', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '日本节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)日|jp|japan', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '新加坡节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)新|sg|singapore', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '美国节点', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)美|us|united states|america', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' },
                { name: '其他国家', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 0, proxies: [], use: [], filter: '(?i)^(?!.*(?:港|hk|台|tw|韩|kr|日|jp|新|sg|美|us)).*$', 'exclude-filter': '', 'exclude-type': '', tolerance: 50, lazy: true, 'max-failed-times': 5, 'disable-udp': false, 'interface-name': '', 'routing-mark': '', 'dialer-proxy': '', 'include-all-proxies': false, 'include-all-providers': false, 'expected-status': '', hidden: false, icon: '' }
            ]
        });

        return {
            tabs,
            panels,
            getDefaultUiState,
            getDefaultConfig
        };
    };
})(window);
