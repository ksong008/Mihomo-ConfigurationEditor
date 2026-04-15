(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createTproxyModule = function (ctx) {
        const { watch, computed, config, uiState, dnsListenPort } = ctx;
        const { parseMarkValue, parseLineList, parseCommaList } = window.MihomoHelpers;

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

        return {
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
        };
    };
})(window);
