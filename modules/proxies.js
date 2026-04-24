(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createProxiesModule = function () {
        const formatYamlMapText = window.MihomoHelpers && typeof window.MihomoHelpers.formatYamlMapText === 'function'
            ? window.MihomoHelpers.formatYamlMapText
            : (value) => {
                try {
                    return JSON.stringify(value || {}, null, 2);
                } catch (err) {
                    return '';
                }
            };
        const formatYamlObjectText = window.MihomoHelpers && typeof window.MihomoHelpers.formatYamlObjectText === 'function'
            ? window.MihomoHelpers.formatYamlObjectText
            : (value) => {
                try {
                    return JSON.stringify(value || {}, null, 2);
                } catch (err) {
                    return '';
                }
            };
        const parseSingleProxyNode = (px) => {
            if (!px) return null;
            const hasRealityOpts = !!(
                px['reality-opts']
                && (
                    String(px['reality-opts']?.['public-key'] || '').trim()
                    || String(px['reality-opts']?.['short-id'] || '').trim()
                    || px['reality-opts']?.['support-x25519mlkem768'] === true
                )
            );

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
                mptcp: px.mptcp || false,
                ip: px.ip || '',
                ipv6: px.ipv6 || '',
                'ip-version': px['ip-version'] || '',
                'interface-name': px['interface-name'] || '',
                'routing-mark': px['routing-mark'] !== undefined && px['routing-mark'] !== null ? px['routing-mark'] : '',
                'packet-encoding': px['packet-encoding'] || '',
                token: px.token || '',
                key: px.key || '',
                uuid: px.uuid || '',
                flow: px.flow || '',
                encryption: px.encryption || '',
                alterId: px.alterId || 0,
                password: px['auth-str'] || px.psk || px.password || '',
                username: px.username || '',
                cipher: px.cipher || 'auto',
                'aead-method': px['aead-method'] || 'chacha20-poly1305',
                'padding-min': px['padding-min'] !== undefined && px['padding-min'] !== null ? px['padding-min'] : '',
                'padding-max': px['padding-max'] !== undefined && px['padding-max'] !== null ? px['padding-max'] : '',
                'table-type': px['table-type'] || 'prefer_ascii',
                'custom-table': px['custom-table'] || '',
                'custom-tables': px['custom-tables'] ? (Array.isArray(px['custom-tables']) ? px['custom-tables'].join('\n') : String(px['custom-tables'])) : '',
                _sudokuHttpmaskText: formatYamlObjectText(px.httpmask),
                'enable-pure-downlink': px['enable-pure-downlink'] || false,
                'global-padding': px['global-padding'] || false,
                'authenticated-length': px['authenticated-length'] || false,
                'ss-opts': {
                    enabled: !!(px['ss-opts'] && px['ss-opts'].enabled),
                    method: px['ss-opts']?.method || 'aes-128-gcm',
                    password: px['ss-opts']?.password || ''
                },
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
                'private-key-passphrase': px['private-key-passphrase'] || '',
                'pre-shared-key': px['pre-shared-key'] || '',
                'host-key': px['host-key'] ? (Array.isArray(px['host-key']) ? px['host-key'].join('\n') : String(px['host-key'])) : '',
                'host-key-algorithms': px['host-key-algorithms'] ? (Array.isArray(px['host-key-algorithms']) ? px['host-key-algorithms'].join('\n') : String(px['host-key-algorithms'])) : '',
                reserved: px.reserved ? (typeof px.reserved === 'object' ? JSON.stringify(px.reserved) : px.reserved) : '',
                'allowed-ips': px['allowed-ips'] ? (Array.isArray(px['allowed-ips']) ? px['allowed-ips'].join('\n') : String(px['allowed-ips'])) : '',
                'persistent-keepalive': px['persistent-keepalive'] !== undefined && px['persistent-keepalive'] !== null ? px['persistent-keepalive'] : '',
                'remote-dns-resolve': px['remote-dns-resolve'] || false,
                dns: px.dns ? (Array.isArray(px.dns) ? px.dns.join('\n') : String(px.dns)) : '',
                _amneziaWgOptionText: formatYamlObjectText(px['amnezia-wg-option']),
                workers: px.workers || 2,
                mtu: px.mtu || 1420,
                'wg-dns': px.dns ? (Array.isArray(px.dns) ? px.dns.join(',') : px.dns) : '',
                up: px.up || '100 Mbps',
                down: px.down || '100 Mbps',
                'obfs-password': px['obfs-password'] || '',
                ports: px.ports || '',
                'hop-interval': px['hop-interval'] || '',
                'congestion-controller': px['congestion-controller'] || 'bbr',
                'bbr-profile': px['bbr-profile'] || '',
                'udp-relay-mode': px['udp-relay-mode'] || 'native',
                'reduce-rtt': px['reduce-rtt'] || false,
                'heartbeat-interval': px['heartbeat-interval'] !== undefined && px['heartbeat-interval'] !== null ? px['heartbeat-interval'] : '',
                heartbeat: px.heartbeat || '10s',
                'request-timeout': px['request-timeout'] || '15s',
                'disable-sni': px['disable-sni'] || false,
                'max-udp-relay-packet-size': px['max-udp-relay-packet-size'] !== undefined && px['max-udp-relay-packet-size'] !== null ? px['max-udp-relay-packet-size'] : '',
                'fast-open': px['fast-open'] || false,
                'max-open-streams': px['max-open-streams'] !== undefined && px['max-open-streams'] !== null ? px['max-open-streams'] : '',
                'recv-window-conn': px['recv-window-conn'] !== undefined && px['recv-window-conn'] !== null ? px['recv-window-conn'] : '',
                'recv-window': px['recv-window'] !== undefined && px['recv-window'] !== null ? px['recv-window'] : '',
                disable_mtu_discovery: px.disable_mtu_discovery || false,
                'udp-over-tcp': px['udp-over-tcp'] || false,
                'udp-over-tcp-version': px['udp-over-tcp-version'] !== undefined && px['udp-over-tcp-version'] !== null ? px['udp-over-tcp-version'] : 1,
                passphrase: px.passphrase || '',
                'obfs-host': px['obfs-host'] || '',
                'port-range': px['port-range'] || '',
                'traffic-pattern': px['traffic-pattern'] || '',
                quic: px.quic || false,
                'max-connections': px['max-connections'] !== undefined && px['max-connections'] !== null ? px['max-connections'] : '',
                'min-streams': px['min-streams'] !== undefined && px['min-streams'] !== null ? px['min-streams'] : '',
                'max-streams': px['max-streams'] !== undefined && px['max-streams'] !== null ? px['max-streams'] : '',
                network: px.type === 'masque' ? (px.network || 'quic') : (px.network || 'tcp'),
                tls: px.tls || false,
                'skip-cert-verify': px['skip-cert-verify'] || false,
                headers: { ...(px.headers || {}) },
                _proxyHeadersText: formatYamlMapText(px.headers),
                servername: px.servername || '',
                certificate: px.certificate || '',
                fingerprint: px.fingerprint || '',
                'client-fingerprint': px['client-fingerprint'] || '',
                alpn: px.alpn ? (Array.isArray(px.alpn) ? px.alpn.join(',') : px.alpn) : '',
                reality: px.reality === false ? false : (hasRealityOpts || !!px.reality),
                'reality-opts': { 'public-key': '', 'short-id': '', 'support-x25519mlkem768': false, ...(px['reality-opts'] || {}) },
                'ech-opts': {
                    enable: !!(px['ech-opts'] && px['ech-opts'].enable),
                    config: px['ech-opts']?.config || '',
                    'query-server-name': px['ech-opts']?.['query-server-name'] || '',
                    pqSignatureSchemesEnabled: !!(px['ech-opts']?.pqSignatureSchemesEnabled)
                },
                smux: {
                    enabled: !!(px.smux && px.smux.enabled),
                    protocol: px.smux?.protocol || 'h2mux',
                    'max-connections': px.smux?.['max-connections'] || 4,
                    'min-streams': px.smux?.['min-streams'] || 0,
                    'max-streams': px.smux?.['max-streams'] || 0,
                    statistic: !!(px.smux?.statistic),
                    'only-tcp': !!(px.smux?.['only-tcp']),
                    padding: !!(px.smux?.padding),
                    'brutal-opts': {
                        enabled: !!(px.smux?.['brutal-opts'] && px.smux?.['brutal-opts'].enabled),
                        up: px.smux?.['brutal-opts']?.up || '',
                        down: px.smux?.['brutal-opts']?.down || ''
                    }
                },
                'ws-opts': {
                    path: px['ws-opts']?.path || '/',
                    headers: { Host: px['ws-opts']?.headers?.Host || '' },
                    'max-early-data': px['ws-opts']?.['max-early-data'] || 0,
                    'early-data-header-name': px['ws-opts']?.['early-data-header-name'] || 'Sec-WebSocket-Protocol',
                    'v2ray-http-upgrade': !!(px['ws-opts']?.['v2ray-http-upgrade']),
                    'v2ray-http-upgrade-fast-open': !!(px['ws-opts']?.['v2ray-http-upgrade-fast-open'])
                },
                'grpc-opts': {
                    'grpc-service-name': px['grpc-opts']?.['grpc-service-name'] || '',
                    'grpc-user-agent': px['grpc-opts']?.['grpc-user-agent'] || '',
                    'ping-interval': px['grpc-opts']?.['ping-interval'] || 0,
                    'max-connections': px['grpc-opts']?.['max-connections'] || 1,
                    'min-streams': px['grpc-opts']?.['min-streams'] || 0,
                    'max-streams': px['grpc-opts']?.['max-streams'] || 0
                },
                'httpupgrade-opts': { host: px['httpupgrade-opts']?.host || '', path: px['httpupgrade-opts']?.path || '/' },
                'h2-opts': { host: px['h2-opts']?.host || '', path: px['h2-opts']?.path || '/' },
                'http-opts': {
                    method: px['http-opts']?.method || 'GET',
                    path: px['http-opts']?.path || '/',
                    host: px['http-opts']?.host || '',
                    headers: { Host: px['http-opts']?.headers?.Host || '' }
                },
                'xhttp-opts': {
                    path: px['xhttp-opts']?.path || '/',
                    host: px['xhttp-opts']?.host || '',
                    mode: px['xhttp-opts']?.mode || 'auto',
                    headers: { ...(px['xhttp-opts']?.headers || {}) },
                    'no-grpc-header': !!(px['xhttp-opts']?.['no-grpc-header']),
                    'x-padding-bytes': px['xhttp-opts']?.['x-padding-bytes'] || '',
                    'x-padding-obfs-mode': !!(px['xhttp-opts']?.['x-padding-obfs-mode']),
                    'x-padding-key': px['xhttp-opts']?.['x-padding-key'] || '',
                    'x-padding-header': px['xhttp-opts']?.['x-padding-header'] || '',
                    'x-padding-placement': px['xhttp-opts']?.['x-padding-placement'] || '',
                    'x-padding-method': px['xhttp-opts']?.['x-padding-method'] || '',
                    'uplink-http-method': px['xhttp-opts']?.['uplink-http-method'] || '',
                    'session-placement': px['xhttp-opts']?.['session-placement'] || '',
                    'session-key': px['xhttp-opts']?.['session-key'] || '',
                    'seq-placement': px['xhttp-opts']?.['seq-placement'] || '',
                    'seq-key': px['xhttp-opts']?.['seq-key'] || '',
                    'reuse-settings': {
                        'max-concurrency': px['xhttp-opts']?.['reuse-settings']?.['max-concurrency'] || '',
                        'max-connections': px['xhttp-opts']?.['reuse-settings']?.['max-connections'] || '',
                        'c-max-reuse-times': px['xhttp-opts']?.['reuse-settings']?.['c-max-reuse-times'] || '',
                        'h-max-request-times': px['xhttp-opts']?.['reuse-settings']?.['h-max-request-times'] || '',
                        'h-max-reusable-secs': px['xhttp-opts']?.['reuse-settings']?.['h-max-reusable-secs'] || '',
                        'h-keep-alive-period': px['xhttp-opts']?.['reuse-settings']?.['h-keep-alive-period'] || 0
                    }
                },
                _wsHeadersText: formatYamlMapText(px['ws-opts']?.headers),
                _httpHeadersText: formatYamlMapText(px['http-opts']?.headers),
                _xhttpHeadersText: formatYamlMapText(px['xhttp-opts']?.headers),
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

        return {
            parseSingleProxyNode
        };
    };
})(window);
