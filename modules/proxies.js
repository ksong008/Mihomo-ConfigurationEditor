(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createProxiesModule = function () {
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

        return {
            parseSingleProxyNode
        };
    };
})(window);
