(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const { parseMarkValue, parseLineList, parseCommaList, getListenPort } = window.MihomoHelpers;

    const sanitizeNftTableName = (value) => (((value || 'mihomo').trim()) || 'mihomo').replace(/[^\w-]+/g, '_');

    const buildRoutingCommands = (nft = {}) => {
        const proxyMark = parseMarkValue(nft && nft.tproxyMarkHex, 111);
        const ipv6 = !!(nft && nft.tproxyIpv6);

        let cmds = `ip rule add fwmark ${proxyMark} table ${proxyMark}\nip route add local 0.0.0.0/0 dev lo table ${proxyMark}`;
        if (ipv6) {
            cmds += `\nip -6 rule add fwmark ${proxyMark} table ${proxyMark}\nip -6 route add local ::/0 dev lo table ${proxyMark}`;
        }
        return cmds;
    };

    const buildSystemdService = (nft = {}) => {
        const nftTable = sanitizeNftTableName(nft && nft.nftTable);
        const proxyMark = parseMarkValue(nft && nft.tproxyMarkHex, 111);
        const ipv6 = !!(nft && nft.tproxyIpv6);

        let script = `[Unit]\nDescription=Mihomo TProxy Routing Rules\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n\n`;
        script += `# 启动前删除旧表（忽略不存在错误）\n`;
        script += `ExecStartPre=-/usr/sbin/nft delete table inet ${nftTable}\n`;
        script += `ExecStart=/usr/sbin/nft -f /etc/mihomo/tproxy.nft\n`;
        script += `ExecStart=/sbin/ip rule add fwmark ${proxyMark} table ${proxyMark}\n`;
        script += `ExecStart=/sbin/ip route add local 0.0.0.0/0 dev lo table ${proxyMark}\n`;
        if (ipv6) {
            script += `ExecStart=/sbin/ip -6 rule add fwmark ${proxyMark} table ${proxyMark}\n`;
            script += `ExecStart=/sbin/ip -6 route add local ::/0 dev lo table ${proxyMark}\n`;
        }

        script += `\n# 停止时删除路由与 nft 表（忽略不存在错误）\n`;
        script += `ExecStop=-/sbin/ip rule del fwmark ${proxyMark} table ${proxyMark}\n`;
        script += `ExecStop=-/sbin/ip route del local 0.0.0.0/0 dev lo table ${proxyMark}\n`;
        if (ipv6) {
            script += `ExecStop=-/sbin/ip -6 rule del fwmark ${proxyMark} table ${proxyMark}\n`;
            script += `ExecStop=-/sbin/ip -6 route del local ::/0 dev lo table ${proxyMark}\n`;
        }
        script += `ExecStop=-/usr/sbin/nft delete table inet ${nftTable}\n`;
        script += `\n[Install]\nWantedBy=multi-user.target`;
        return script;
    };

    const buildCleanNftablesScript = (options = {}) => {
        const nft = options.nft || {};
        const config = options.config || {};
        const table = sanitizeNftTableName(nft.nftTable);
        const tproxyPort = Number(config['tproxy-port'] || nft.tproxyPort || 7894);
        const dnsPort = getListenPort(config.dns && config.dns.listen, 53);

        const proxyMark = parseMarkValue(nft.tproxyMarkHex, 111);
        const routeMark = parseMarkValue(nft.routeMarkHex, 112);

        const ingressIface = (nft.ingressIface || '').trim();
        const egressIface = (nft.egressIface || config['interface-name'] || '').trim();

        const proxyUid = String(nft.proxyUid || '').trim();
        const proxyGid = String(nft.proxyGid || '').trim();
        const hasUidGid = !!(proxyUid && proxyGid);

        const ipv6 = !!nft.tproxyIpv6;
        const hijackDns = !!nft.hijackDns;
        const bypassCnIp = !!nft.bypassCnIp;
        const filterPorts = !!nft.filterPorts;

        const commonPorts = parseCommaList(nft.commonPorts).join(', ');
        const fakeIpRange = (config.dns && config.dns['enhanced-mode'] === 'fake-ip' && config.dns['fake-ip-range'])
            ? config.dns['fake-ip-range']
            : '';

        const private4 = parseLineList(nft.privateIps).filter(cidr => !fakeIpRange || cidr !== fakeIpRange);
        const private6 = parseLineList(nft.privateIpsV6);
        const cn4 = parseLineList(nft.cnIps);
        const cn6 = parseLineList(nft.cnIpsV6);

        const defineLines = [
            `define TPROXY_PORT   = ${tproxyPort}`,
            `define PROXY_MARK    = ${proxyMark}`,
            `define ROUTE_MARK    = ${routeMark}`
        ];

        if (hasUidGid) {
            defineLines.push(`define PROXY_UID     = ${proxyUid}`);
            defineLines.push(`define PROXY_GID     = ${proxyGid}`);
        }

        if (ingressIface) {
            defineLines.push(`define INGRESS_IFACE = "${ingressIface}"`);
        }

        if (egressIface) {
            defineLines.push(`define EGRESS_IFACE  = "${egressIface}"`);
        }

        const tableLines = [];
        const pushTableLine = (line = '') => tableLines.push(line);
        const pushTableBlock = (header, bodyLines) => {
            pushTableLine(`${header} {`);
            bodyLines.forEach((line) => pushTableLine(`    ${line}`));
            pushTableLine('}');
        };

        pushTableBlock('set private_ip', [
            'type ipv4_addr',
            'flags interval',
            `elements = { ${private4.length ? private4.join(', ') : '127.0.0.0/8'} }`
        ]);

        if (ipv6) {
            pushTableLine();
            pushTableBlock('set private_ip6', [
                'type ipv6_addr',
                'flags interval',
                `elements = { ${private6.length ? private6.join(', ') : '::1/128'} }`
            ]);
        }

        if (bypassCnIp && cn4.length) {
            pushTableLine();
            pushTableBlock('set cn_ip', [
                'type ipv4_addr',
                'flags interval',
                `elements = { ${cn4.join(', ')} }`
            ]);
        }

        if (bypassCnIp && ipv6 && cn6.length) {
            pushTableLine();
            pushTableBlock('set cn_ip6', [
                'type ipv6_addr',
                'flags interval',
                `elements = { ${cn6.join(', ')} }`
            ]);
        }

        if (hijackDns) {
            pushTableLine();
            const preroutingDnsRules = [];
            if (ingressIface) {
                preroutingDnsRules.push('iifname != "lo" iifname != $INGRESS_IFACE accept');
            }
            preroutingDnsRules.push(`meta l4proto { tcp, udp } th dport 53 redirect to :${dnsPort}`);
            pushTableBlock('chain prerouting_dns', [
                'type nat hook prerouting priority dstnat; policy accept;',
                ...preroutingDnsRules
            ]);

            pushTableLine();
            const outputDnsRules = [];
            if (hasUidGid) {
                outputDnsRules.push('meta skuid $PROXY_UID meta skgid $PROXY_GID accept');
            } else {
                outputDnsRules.push('oifname "lo" accept');
            }
            outputDnsRules.push(`meta l4proto { tcp, udp } th dport 53 redirect to :${dnsPort}`);
            pushTableBlock('chain output_dns', [
                'type nat hook output priority dstnat; policy accept;',
                ...outputDnsRules
            ]);
        }

        pushTableLine();
        const preroutingRules = [];
        if (ingressIface) {
            preroutingRules.push('iifname != "lo" iifname != $INGRESS_IFACE accept');
        }
        if (hijackDns) {
            preroutingRules.push('meta l4proto { tcp, udp } th dport 53 accept');
        }
        preroutingRules.push(
            'fib daddr type local accept',
            'ip daddr @private_ip accept'
        );
        if (bypassCnIp && cn4.length) {
            preroutingRules.push('ip daddr @cn_ip accept');
        }
        if (!ipv6) {
            preroutingRules.push('meta nfproto ipv6 accept');
        }
        if (filterPorts && commonPorts) {
            if (fakeIpRange) {
                preroutingRules.push(`ip daddr != ${fakeIpRange} tcp dport != { ${commonPorts} } accept`);
                preroutingRules.push(`ip daddr != ${fakeIpRange} udp dport != { ${commonPorts} } accept`);
            } else {
                preroutingRules.push(`tcp dport != { ${commonPorts} } accept`);
                preroutingRules.push(`udp dport != { ${commonPorts} } accept`);
            }
        }
        preroutingRules.push(
            'meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable',
            'meta l4proto tcp socket transparent 1 meta mark set $PROXY_MARK accept',
            'meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_MARK'
        );
        pushTableBlock('chain prerouting_tproxy', [
            'type filter hook prerouting priority mangle; policy accept;',
            ...preroutingRules
        ]);

        pushTableLine();
        const outputRules = [];
        if (egressIface) {
            outputRules.push('oifname != $EGRESS_IFACE accept');
        }
        outputRules.push(
            'ct direction reply accept',
            'meta mark $ROUTE_MARK accept'
        );
        if (hasUidGid) {
            outputRules.push('meta skuid $PROXY_UID meta skgid $PROXY_GID meta mark set $ROUTE_MARK accept');
        }
        if (hijackDns) {
            outputRules.push('meta l4proto { tcp, udp } th dport 53 accept');
        }
        outputRules.push(
            'fib daddr type local accept',
            'ip daddr @private_ip accept'
        );
        if (bypassCnIp && cn4.length) {
            outputRules.push('ip daddr @cn_ip accept');
        }
        if (!ipv6) {
            outputRules.push('meta nfproto ipv6 accept');
        }
        if (filterPorts && commonPorts) {
            if (fakeIpRange) {
                outputRules.push(`ip daddr != ${fakeIpRange} tcp dport != { ${commonPorts} } accept`);
                outputRules.push(`ip daddr != ${fakeIpRange} udp dport != { ${commonPorts} } accept`);
            } else {
                outputRules.push(`tcp dport != { ${commonPorts} } accept`);
                outputRules.push(`udp dport != { ${commonPorts} } accept`);
            }
        }
        outputRules.push('meta l4proto { tcp, udp } meta mark set $PROXY_MARK');
        pushTableBlock('chain output_tproxy', [
            'type route hook output priority mangle; policy accept;',
            ...outputRules
        ]);

        if (ipv6) {
            pushTableLine();
            const preroutingV6Rules = [];
            if (ingressIface) {
                preroutingV6Rules.push('iifname != "lo" iifname != $INGRESS_IFACE accept');
            }
            if (hijackDns) {
                preroutingV6Rules.push('meta l4proto { tcp, udp } th dport 53 accept');
            }
            preroutingV6Rules.push(
                'fib daddr type local accept',
                'ip6 daddr @private_ip6 accept'
            );
            if (bypassCnIp && cn6.length) {
                preroutingV6Rules.push('ip6 daddr @cn_ip6 accept');
            }
            preroutingV6Rules.push(
                'meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable',
                'meta l4proto tcp socket transparent 1 meta mark set $PROXY_MARK accept',
                'meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_MARK'
            );
            pushTableBlock('chain prerouting_tproxy_v6', [
                'type filter hook prerouting priority mangle; policy accept;',
                ...preroutingV6Rules
            ]);

            pushTableLine();
            const outputV6Rules = [];
            if (egressIface) {
                outputV6Rules.push('oifname != $EGRESS_IFACE accept');
            }
            outputV6Rules.push(
                'ct direction reply accept',
                'meta mark $ROUTE_MARK accept'
            );
            if (hasUidGid) {
                outputV6Rules.push('meta skuid $PROXY_UID meta skgid $PROXY_GID meta mark set $ROUTE_MARK accept');
            }
            if (hijackDns) {
                outputV6Rules.push('meta l4proto { tcp, udp } th dport 53 accept');
            }
            outputV6Rules.push(
                'fib daddr type local accept',
                'ip6 daddr @private_ip6 accept'
            );
            if (bypassCnIp && cn6.length) {
                outputV6Rules.push('ip6 daddr @cn_ip6 accept');
            }
            outputV6Rules.push('meta l4proto { tcp, udp } meta mark set $PROXY_MARK');
            pushTableBlock('chain output_tproxy_v6', [
                'type route hook output priority mangle; policy accept;',
                ...outputV6Rules
            ]);
        }

        return [
            '#!/usr/sbin/nft -f',
            '',
            ...defineLines,
            `destroy table inet ${table}`,
            '',
            `table inet ${table} {`,
            ...tableLines.map((line) => line ? `    ${line}` : ''),
            '}',
            ''
        ].join('\n');
    };

    const buildInstallScript = (cleanNftablesScript, systemdService) => {
        return `#!/bin/bash\n# 一键部署 Mihomo 透明代理持久化环境\nmkdir -p /etc/mihomo\n\n# 1. 写入 nftables 规则\ncat > /etc/mihomo/tproxy.nft << 'EOF'\n${cleanNftablesScript}\nEOF\n\n# 2. 写入 Systemd 服务\ncat > /etc/systemd/system/mihomo-tproxy.service << 'EOF'\n${systemdService}\nEOF\n\n# 3. 重新加载并启用服务\nsystemctl daemon-reload\nsystemctl enable --now mihomo-tproxy\necho "Mihomo 透明代理规则已持久化部署并启动！"`;
    };

    window.MihomoFeatureModules.TproxyBuilders = Object.freeze({
        sanitizeNftTableName,
        buildRoutingCommands,
        buildSystemdService,
        buildCleanNftablesScript,
        buildInstallScript
    });
})(window);
