(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createDnsModule = function (ctx) {
        const { ref, computed, watch, config, uiState } = ctx;
        const { parseCommaList, getListenPort } = window.MihomoHelpers;

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

        return {
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
        };
    };
})(window);
