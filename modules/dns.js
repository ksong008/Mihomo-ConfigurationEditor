(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createDnsModule = function (ctx) {
        const { ref, computed, watch, config, uiState } = ctx;
        const { parseCommaList, getListenPort, normalizeListenAddress, replaceListenPort } = window.MihomoHelpers;
        const DEFAULT_FAKE_IP_RANGE6 = 'fdfe:dcba:9876::1/64';

        const normalizeDnsListenText = (val, fallback = ':53') => normalizeListenAddress(val, fallback);

        const dnsListenPortInput = computed({
            get() {
                return config.value.dns && config.value.dns.listen !== undefined && config.value.dns.listen !== null
                    ? String(config.value.dns.listen)
                    : ':53';
            },
            set(val) {
                if (!config.value.dns) config.value.dns = {};
                config.value.dns.listen = String(val ?? '');
            }
        });

        const normalizeDnsListenInput = () => {
            if (!config.value.dns) return;
            config.value.dns.listen = normalizeDnsListenText(config.value.dns.listen, ':53');
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
        const localDnsForwardTargetPort = computed(() => dnsListenPort.value === 53 ? 1053 : dnsListenPort.value);

        const specifiedProxyPortList = computed(() =>
            parseCommaList((uiState.value.nftablesConfig && uiState.value.nftablesConfig.commonPorts) || '')
                .map(s => String(s).trim())
                .filter(Boolean)
        );

        const specifiedPortsContain53 = computed(() =>
            !!(uiState.value.nftablesConfig && uiState.value.nftablesConfig.filterPorts && specifiedProxyPortList.value.includes('53'))
        );

        const dnsPathPreview = computed(() => {
            const listen = normalizeDnsListenText(config.value.dns && config.value.dns.listen, ':53');

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
                    title: '检测到 DNS 劫持与本地 53 前端转发同时声明',
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
                    title: '已声明使用本地 53 前端转发',
                    lines: [
                        '客户端 -> 192.168.1.1:53',
                        '-> 本机 53 前端服务',
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
                    title: '透明代理已开启，但 DNS 未被强制接管',
                    lines: [
                        '客户端 -> 客户端当前配置的 DNS:53',
                        '典型 OpenWrt / DHCP 场景下，通常会先到路由器 53。',
                        '这不等于自动劫持；手动指定外部 DNS 的客户端仍可能绕过 Mihomo。',
                        '如需稳定域名分流，请开启 DNS 劫持或使用本地 53 端口转发'
                    ]
                };
            }

            return {
                tone: 'slate',
                title: '按客户端 / DHCP DNS 配置决定',
                lines: [
                    '当前既未启用透明代理 DNS 劫持，也未使用本地 53 端口转发。',
                    '典型 OpenWrt / DHCP 场景下，多数客户端会先请求路由器 53；这仍不是自动劫持。',
                    `只有客户端本来就把 DNS 指向 ${listen}，或由前端 53 服务再转发到这里，请求才会进入 Mihomo 内置 DNS。`
                ]
            };
        });

        const ensureSafeDnsListenPortForTransparentProxy = () => {
            if (!(config.value.dns && config.value.dns.enable)) return false;
            if (dnsListenPort.value !== 53) return false;

            config.value.dns.listen = replaceListenPort(config.value.dns.listen, 1053);
            return true;
        };

        watch(
            [
                () => String(config.value?.dns?.['enhanced-mode'] || '').trim(),
                () => !!config.value?.dns?.ipv6
            ],
            ([enhancedMode, ipv6Enabled]) => {
                if (!config.value.dns) return;
                if (enhancedMode !== 'fake-ip' || !ipv6Enabled) return;
                if (String(config.value.dns['fake-ip-range6'] || '').trim()) return;
                config.value.dns['fake-ip-range6'] = DEFAULT_FAKE_IP_RANGE6;
            },
            { immediate: true }
        );

        return {
            dnsListenPortInput,
            normalizeDnsListenInput,
            dnsListenPort,
            showHostsEditor,
            usingTransparentProxy,
            dnsHijackEnabled,
            dnsForwardConflict,
            dnsLocalForwardNeedsNon53,
            localDnsForwardTargetPort,
            specifiedPortsContain53,
            dnsPathPreview,
            ensureSafeDnsListenPortForTransparentProxy
        };
    };
})(window);
