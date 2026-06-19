import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'mihomo.helpers.js',
        'modules/tproxy-builders.js'
    ]
});

test('tproxy builders sanitize nft table names and routing commands', async () => {
    const runtime = await runtimePromise;
    const {
        sanitizeNftTableName,
        buildRoutingCommands
    } = runtime.window.MihomoFeatureModules.TproxyBuilders;

    assert.equal(sanitizeNftTableName(' mihomo table! '), 'mihomo_table_');
    assert.equal(sanitizeNftTableName(''), 'mihomo');
    assert.equal(
        buildRoutingCommands({ tproxyMarkHex: '111', tproxyIpv6: true }),
        [
            'ip rule add fwmark 111 table 111',
            'ip route add local 0.0.0.0/0 dev lo table 111',
            'ip -6 rule add fwmark 111 table 111',
            'ip -6 route add local ::/0 dev lo table 111'
        ].join('\n')
    );
});

test('tproxy builders generate systemd routing service with explicit CIDR routes', async () => {
    const runtime = await runtimePromise;
    const { buildSystemdService } = runtime.window.MihomoFeatureModules.TproxyBuilders;
    const service = buildSystemdService({
        nftTable: 'mihomo-prod',
        tproxyMarkHex: '112',
        tproxyIpv6: true
    });

    assert.match(service, /ExecStartPre=-\/usr\/sbin\/nft delete table inet mihomo-prod/);
    assert.match(service, /ExecStart=\/sbin\/ip route add local 0\.0\.0\.0\/0 dev lo table 112/);
    assert.match(service, /ExecStart=\/sbin\/ip -6 route add local ::\/0 dev lo table 112/);
    assert.match(service, /ExecStop=-\/sbin\/ip route del local 0\.0\.0\.0\/0 dev lo table 112/);
    assert.match(service, /ExecStop=-\/sbin\/ip -6 route del local ::\/0 dev lo table 112/);
});

test('tproxy builders generate clean nftables ruleset with defines and filters', async () => {
    const runtime = await runtimePromise;
    const { buildCleanNftablesScript } = runtime.window.MihomoFeatureModules.TproxyBuilders;
    const script = buildCleanNftablesScript({
        config: {
            'tproxy-port': 7895,
            'interface-name': 'eth0',
            dns: {
                listen: ':1053',
                'enhanced-mode': 'fake-ip',
                'fake-ip-range': '198.18.0.0/16'
            }
        },
        nft: {
            nftTable: 'mihomo-prod',
            tproxyMarkHex: '111',
            routeMarkHex: '112',
            ingressIface: 'br-lan',
            egressIface: '',
            proxyUid: '1000',
            proxyGid: '1000',
            tproxyIpv6: true,
            hijackDns: true,
            bypassCnIp: true,
            filterPorts: true,
            commonPorts: '80,443',
            privateIps: '10.0.0.0/8\n198.18.0.0/16',
            privateIpsV6: 'fc00::/7',
            cnIps: '1.0.1.0/24',
            cnIpsV6: '240e::/16'
        }
    });

    assert.match(script, /^#!\/usr\/sbin\/nft -f/);
    assert.match(script, /define TPROXY_PORT   = 7895/);
    assert.match(script, /define INGRESS_IFACE = "br-lan"/);
    assert.match(script, /define EGRESS_IFACE  = "eth0"/);
    assert.match(script, /destroy table inet mihomo-prod/);
    assert.doesNotMatch(script, /198\.18\.0\.0\/16, 198\.18\.0\.0\/16/);
    assert.match(script, /meta l4proto \{ tcp, udp \} th dport 53 redirect to :1053/);
    assert.match(script, /ip daddr != 198\.18\.0\.0\/16 tcp dport != \{ 80, 443 \} accept/);
    assert.match(script, /chain prerouting_tproxy_v6/);
    assert.match(script, /ip6 daddr @cn_ip6 accept/);
});

test('tproxy builders compose install script from clean nftables and systemd service', async () => {
    const runtime = await runtimePromise;
    const { buildInstallScript } = runtime.window.MihomoFeatureModules.TproxyBuilders;
    const script = buildInstallScript('nft rules', 'systemd unit');

    assert.match(script, /cat > \/etc\/mihomo\/tproxy\.nft << 'EOF'\nnft rules\nEOF/);
    assert.match(script, /cat > \/etc\/systemd\/system\/mihomo-tproxy\.service << 'EOF'\nsystemd unit\nEOF/);
    assert.match(script, /systemctl enable --now mihomo-tproxy/);
});
