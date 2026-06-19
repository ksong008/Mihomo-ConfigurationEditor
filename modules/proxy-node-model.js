(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const proxySchema = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxySchema;
    if (!proxySchema) {
        throw new Error('ProxySchema 未加载，请确认先引入 ./modules/proxy-schema.js');
    }

    const proxyNodeUtils = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxyNodeUtils;
    if (!proxyNodeUtils) {
        throw new Error('ProxyNodeUtils 未加载，请确认先引入 ./modules/proxy-node-utils.js');
    }

    const { getProxyCapabilitySchema } = proxySchema;
    const {
        normalizeOpenvpnProtoValue,
        normalizeOpenvpnCipherValue,
        normalizeOpenvpnAuthValue,
        normalizeOpenvpnCompLzoValue,
        formatScalarListText,
        isPlainObject
    } = proxyNodeUtils;

    const fallbackFormatObjectText = (value) => {
        try {
            return JSON.stringify(value || {}, null, 2);
        } catch (err) {
            return '';
        }
    };

    const createProxyNodeModel = (options = {}) => {
        const formatYamlMapText = typeof options.formatYamlMapText === 'function'
            ? options.formatYamlMapText
            : fallbackFormatObjectText;
        const formatYamlObjectText = typeof options.formatYamlObjectText === 'function'
            ? options.formatYamlObjectText
            : fallbackFormatObjectText;

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
            const proxyType = String(px.type || 'vless').trim() || 'vless';
            const typeCapabilities = getProxyCapabilitySchema(proxyType);
            const typeFeatures = typeCapabilities.features;
            const defaultNetwork = typeCapabilities.networkOptions[0]?.value || 'tcp';

            const base = {
                name: px.name || `Node-${Math.floor(Math.random() * 1000)}`,
                type: proxyType,
                server: px.server || '',
                port: portVal || 443,
                udp: proxyType === 'snell' ? px.udp === true : px.udp !== false,
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
                cipher: proxyType === 'openvpn' ? normalizeOpenvpnCipherValue(px.cipher) : (px.cipher || 'auto'),
                proto: proxyType === 'openvpn' ? normalizeOpenvpnProtoValue(px.proto) : (px.proto || 'udp'),
                dev: proxyType === 'openvpn' ? String(px.dev || 'tun').trim().toLowerCase() : (px.dev || 'tun'),
                auth: proxyType === 'openvpn' ? normalizeOpenvpnAuthValue(px.auth) : (px.auth || 'SHA256'),
                'comp-lzo': proxyType === 'openvpn' ? normalizeOpenvpnCompLzoValue(px['comp-lzo']) : (px['comp-lzo'] || ''),
                ca: px.ca || '',
                cert: px.cert || '',
                'tls-crypt': px['tls-crypt'] || '',
                ping: px.ping !== undefined && px.ping !== null ? px.ping : '',
                'ping-restart': px['ping-restart'] !== undefined && px['ping-restart'] !== null ? px['ping-restart'] : '',
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
                version: proxyType === 'snell'
                    ? String(px.version ?? '').trim().replace(/^v/i, '')
                    : (px.version || '4'),
                reuse: px.reuse || false,
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
                mtu: px.mtu !== undefined && px.mtu !== null ? px.mtu : (proxyType === 'openvpn' ? '' : 1420),
                'wg-dns': px.dns ? (Array.isArray(px.dns) ? px.dns.join(',') : px.dns) : '',
                up: px.up || '100 Mbps',
                down: px.down || '100 Mbps',
                'obfs-password': px['obfs-password'] || '',
                'obfs-min-packet-size': px['obfs-min-packet-size'] !== undefined && px['obfs-min-packet-size'] !== null ? px['obfs-min-packet-size'] : '',
                'obfs-max-packet-size': px['obfs-max-packet-size'] !== undefined && px['obfs-max-packet-size'] !== null ? px['obfs-max-packet-size'] : '',
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
                network: px.network || defaultNetwork,
                tls: typeCapabilities.tlsMode === 'required' ? px.tls !== false : !!px.tls,
                'skip-cert-verify': px['skip-cert-verify'] || false,
                headers: { ...(px.headers || {}) },
                _proxyHeadersText: formatYamlMapText(px.headers),
                servername: px.servername || px.sni || '',
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
                    'max-connections': px['grpc-opts']?.['max-connections'] !== undefined && px['grpc-opts']?.['max-connections'] !== null ? px['grpc-opts']?.['max-connections'] : 1,
                    'min-streams': px['grpc-opts']?.['min-streams'] !== undefined && px['grpc-opts']?.['min-streams'] !== null ? px['grpc-opts']?.['min-streams'] : 0,
                    'max-streams': px['grpc-opts']?.['max-streams'] !== undefined && px['grpc-opts']?.['max-streams'] !== null ? px['grpc-opts']?.['max-streams'] : 0
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
                    'uplink-data-placement': px['xhttp-opts']?.['uplink-data-placement'] || '',
                    'uplink-data-key': px['xhttp-opts']?.['uplink-data-key'] || '',
                    'uplink-chunk-size': px['xhttp-opts']?.['uplink-chunk-size'] || '',
                    'session-placement': px['xhttp-opts']?.['session-placement'] || '',
                    'session-key': px['xhttp-opts']?.['session-key'] || '',
                    'seq-placement': px['xhttp-opts']?.['seq-placement'] || '',
                    'seq-key': px['xhttp-opts']?.['seq-key'] || '',
                    'sc-max-each-post-bytes': px['xhttp-opts']?.['sc-max-each-post-bytes'] || '',
                    'sc-min-posts-interval-ms': px['xhttp-opts']?.['sc-min-posts-interval-ms'] !== undefined && px['xhttp-opts']?.['sc-min-posts-interval-ms'] !== null ? px['xhttp-opts']?.['sc-min-posts-interval-ms'] : '',
                    'reuse-settings': {
                        'max-concurrency': px['xhttp-opts']?.['reuse-settings']?.['max-concurrency'] || '',
                        'max-connections': px['xhttp-opts']?.['reuse-settings']?.['max-connections'] || '',
                        'c-max-reuse-times': px['xhttp-opts']?.['reuse-settings']?.['c-max-reuse-times'] || '',
                        'h-max-request-times': px['xhttp-opts']?.['reuse-settings']?.['h-max-request-times'] || '',
                        'h-max-reusable-secs': px['xhttp-opts']?.['reuse-settings']?.['h-max-reusable-secs'] || '',
                        'h-keep-alive-period': px['xhttp-opts']?.['reuse-settings']?.['h-keep-alive-period'] || 0
                    },
                    'download-settings': isPlainObject(px['xhttp-opts']?.['download-settings']) ? { ...(px['xhttp-opts']?.['download-settings'] || {}) } : {}
                },
                _wsHeadersText: formatYamlMapText(px['ws-opts']?.headers),
                _httpHeadersText: formatYamlMapText(px['http-opts']?.headers),
                _xhttpHeadersText: formatYamlMapText(px['xhttp-opts']?.headers),
                _h2HostsText: formatScalarListText(px['h2-opts']?.host),
                _httpPathsText: formatScalarListText(px['http-opts']?.path),
                _xhttpDownloadSettingsText: formatYamlObjectText(px['xhttp-opts']?.['download-settings']),
                'idle-session-check-interval': px['idle-session-check-interval'] || '30s',
                'idle-session-timeout': px['idle-session-timeout'] || '30s',
                'min-idle-session': px['min-idle-session'] || 0,
                transport: px.transport || 'TCP',
                multiplexing: px.multiplexing || 'MULTIPLEXING_OFF',
                'dialer-proxy': px['dialer-proxy'] || ''
            };

            if (base['http-opts'] && base['http-opts'].headers && base['http-opts'].headers.Host) {
                base['http-opts'].host = Array.isArray(base['http-opts'].headers.Host)
                    ? base['http-opts'].headers.Host[0]
                    : base['http-opts'].headers.Host;
            }
            if (typeFeatures.tuicProfile && !base.uuid) base.uuid = px.uuid || '';
            return base;
        };

        return {
            parseSingleProxyNode
        };
    };

    window.MihomoFeatureModules.ProxyNodeModel = Object.freeze({
        createProxyNodeModel
    });
})(window);
