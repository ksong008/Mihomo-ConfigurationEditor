(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createProxiesModule = function () {
        const parseYamlMapText = window.MihomoHelpers && typeof window.MihomoHelpers.parseYamlMapText === 'function'
            ? window.MihomoHelpers.parseYamlMapText
            : () => undefined;
        const parseYamlObjectText = window.MihomoHelpers && typeof window.MihomoHelpers.parseYamlObjectText === 'function'
            ? window.MihomoHelpers.parseYamlObjectText
            : () => undefined;
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
        const proxySchema = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxySchema;
        if (!proxySchema) {
            throw new Error('ProxySchema 未加载，请确认先引入 ./modules/proxy-schema.js');
        }
        const proxyNodeUtils = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxyNodeUtils;
        if (!proxyNodeUtils) {
            throw new Error('ProxyNodeUtils 未加载，请确认先引入 ./modules/proxy-node-utils.js');
        }
        const {
            VLESS_FLOW_OPTIONS,
            PACKET_ENCODING_OPTIONS,
            VMESS_CIPHER_OPTIONS,
            HYSTERIA_PROTOCOL_OPTIONS,
            HYSTERIA2_OBFS_OPTIONS,
            BBR_PROFILE_OPTIONS,
            TUIC_UDP_RELAY_MODE_OPTIONS,
            QUIC_CONGESTION_CONTROLLER_OPTIONS,
            MASQUE_CONGESTION_CONTROLLER_OPTIONS,
            OPENVPN_PROTO_OPTIONS,
            OPENVPN_DEV_OPTIONS,
            OPENVPN_CIPHER_OPTIONS,
            OPENVPN_AUTH_OPTIONS,
            OPENVPN_COMP_LZO_OPTIONS,
            SNELL_VERSION_OPTIONS,
            SNELL_UDP_VERSION_OPTIONS,
            MIERU_TRANSPORT_OPTIONS,
            MIERU_MULTIPLEXING_OPTIONS,
            XHTTP_MODE_OPTIONS,
            XHTTP_PADDING_PLACEMENT_OPTIONS,
            XHTTP_PADDING_METHOD_OPTIONS,
            XHTTP_UPLINK_HTTP_METHOD_OPTIONS,
            XHTTP_UPLINK_DATA_PLACEMENT_OPTIONS,
            XHTTP_KEY_PLACEMENT_OPTIONS,
            XHTTP_DOWNLOAD_SETTINGS_ALLOWED_KEYS,
            XHTTP_DOWNLOAD_SETTINGS_REUSE_ALLOWED_KEYS,
            getProxyCapabilitySchema,
            getProxyNetworkOptions,
            proxySupportsTransport,
            getProxyTlsMode,
            proxySupportsToggle,
            proxySupportsTlsClientFingerprint,
            getProxyTlsServerNameKey,
            getProxyTlsServerNameValue,
            proxyHasTlsSection,
            resolveProxyCapabilities,
            proxyToggleAvailableInCurrentNetwork,
            sanitizeProxyByCapabilities
        } = proxySchema;
        const {
            normalizeOpenvpnProtoValue,
            normalizeOpenvpnCipherValue,
            normalizeOpenvpnAuthValue,
            normalizeOpenvpnCompLzoValue,
            formatScalarListText,
            parseScalarListText,
            hasTextValue,
            isValidPortRangeListText,
            isValidHy2HopIntervalText,
            isValidIntegerText,
            isValidPositiveIntegerOrRangeText,
            isPlainObject,
            sanitizeXhttpDownloadSettings,
            collectUnsupportedXhttpDownloadSettingsKeys,
            pruneEmptyYamlValue,
            compactWithDefaults
        } = proxyNodeUtils;
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

            if (base['http-opts']) {
                if (base['http-opts'].headers && base['http-opts'].headers.Host) {
                    base['http-opts'].host = Array.isArray(base['http-opts'].headers.Host)
                        ? base['http-opts'].headers.Host[0]
                        : base['http-opts'].headers.Host;
                }
            }
            if (typeFeatures.tuicProfile && !base.uuid) base.uuid = px.uuid || '';
            return base;
        };
        const getProxyValidationIssues = (proxy) => {
            const parsed = parseSingleProxyNode(proxy);
            if (!parsed) return [];

            const issues = [];
            const typeDefaults = parseSingleProxyNode({ type: parsed.type }) || {};
            const caps = resolveProxyCapabilities(proxy);
            const { defaultNetwork, effectiveNetwork, requestedNetwork, supportsTransport } = caps;
            const smux = parsed.smux || {};
            const smuxEnabled = !!smux.enabled;
            const brutalEnabled = !!smux['brutal-opts']?.enabled;
            const fingerprint = String(parsed.fingerprint || '').trim();
            const serverName = getProxyTlsServerNameValue(proxy);
            const clientFingerprint = String(parsed['client-fingerprint'] || '').trim();
            const realityEnabled = !!parsed.reality;
            const realityPublicKey = String(parsed['reality-opts']?.['public-key'] || '').trim();
            const smuxMaxConnections = Number(smux['max-connections'] || 0);
            const smuxMinStreams = Number(smux['min-streams'] || 0);
            const smuxMaxStreams = Number(smux['max-streams'] || 0);
            const grpcMaxConnections = Number(parsed['grpc-opts']?.['max-connections'] || 0);
            const grpcMinStreams = Number(parsed['grpc-opts']?.['min-streams'] || 0);
            const grpcMaxStreams = Number(parsed['grpc-opts']?.['max-streams'] || 0);
            const trustTunnelMaxConnections = Number(parsed['max-connections'] || 0);
            const trustTunnelMinStreams = Number(parsed['min-streams'] || 0);
            const trustTunnelMaxStreams = Number(parsed['max-streams'] || 0);
            const defaultSmuxMaxConnections = Number(typeDefaults.smux?.['max-connections'] || 0);
            const defaultGrpcMaxConnections = Number(typeDefaults['grpc-opts']?.['max-connections'] || 0);
            const packetEncoding = String(parsed['packet-encoding'] || '').trim();
            const flow = String(parsed.flow || '').trim();
            const vmessCipher = String(parsed.cipher || '').trim();
            const ssCipher = String(parsed.cipher || '').trim();
            const password = String(parsed.password || '').trim();
            const token = String(parsed.token || '').trim();
            const uuid = String(parsed.uuid || '').trim();
            const username = String(parsed.username || '').trim();
            const privateKey = String(parsed['private-key'] || '').trim();
            const publicKey = String(parsed['public-key'] || '').trim();
            const ipAddress = String(parsed.ip || '').trim();
            const snellVersion = String(proxy?.version || '').trim().replace(/^v/i, '');
            const hysteriaProtocol = String(parsed.protocol || '').trim();
            const hysteria2Obfs = String(parsed.obfs || '').trim();
            const tuicUdpRelayMode = String(parsed['udp-relay-mode'] || '').trim();
            const congestionController = String(parsed['congestion-controller'] || '').trim();
            const dnsEntries = parseScalarListText(parsed.dns);
            const hasTrojanSsOpts = !!parsed['ss-opts']?.enabled;
            const trojanSsPassword = String(parsed['ss-opts']?.password || '').trim();
            const sshHasPassword = password.length > 0;
            const sshHasPrivateKey = privateKey.length > 0;
            const sshPrivateKeyPassphrase = String(parsed['private-key-passphrase'] || '').trim();
            const hasMieruPortRange = String(parsed['port-range'] || '').trim().length > 0;
            const mieruTransport = String(parsed.transport || '').trim();
            const mieruMultiplexing = String(parsed.multiplexing || '').trim();
            const hy2Ports = String(parsed.ports || '').trim();
            const hy2HopInterval = String(parsed['hop-interval'] || '').trim();
            const bbrProfile = String(parsed['bbr-profile'] || '').trim();
            const openvpnProto = String(parsed.proto || '').trim().toLowerCase();
            const openvpnDev = String(parsed.dev || '').trim().toLowerCase();
            const openvpnCipher = String(parsed.cipher || '').trim().toUpperCase();
            const openvpnAuth = String(parsed.auth || '').trim().toUpperCase();
            const openvpnCompLzo = String(parsed['comp-lzo'] || '').trim().toLowerCase();
            const openvpnCa = String(parsed.ca || '').trim();
            const openvpnCert = String(parsed.cert || '').trim();
            const openvpnKey = String(parsed.key || '').trim();
            const openvpnUsername = String(parsed.username || '').trim();
            const openvpnPing = String(parsed.ping ?? '').trim();
            const openvpnPingRestart = String(parsed['ping-restart'] ?? '').trim();
            const openvpnMtu = String(parsed.mtu ?? '').trim();
            const wsHttpUpgradeEnabled = !!parsed['ws-opts']?.['v2ray-http-upgrade'];
            const wsHttpUpgradeFastOpenEnabled = !!parsed['ws-opts']?.['v2ray-http-upgrade-fast-open'];
            const xhttpOptions = parsed['xhttp-opts'] || {};
            const xhttpMode = String(xhttpOptions.mode || '').trim();
            const xPaddingObfsMode = !!xhttpOptions['x-padding-obfs-mode'];
            const xPaddingBytes = String(xhttpOptions['x-padding-bytes'] || '').trim();
            const xPaddingPlacement = String(xhttpOptions['x-padding-placement'] || '').trim();
            const xPaddingHeader = String(xhttpOptions['x-padding-header'] || '').trim();
            const xPaddingKey = String(xhttpOptions['x-padding-key'] || '').trim();
            const xPaddingMethod = String(xhttpOptions['x-padding-method'] || '').trim();
            const uplinkHttpMethod = String(xhttpOptions['uplink-http-method'] || '').trim();
            const uplinkDataPlacement = String(xhttpOptions['uplink-data-placement'] || '').trim();
            const uplinkDataKey = String(xhttpOptions['uplink-data-key'] || '').trim();
            const uplinkChunkSize = String(xhttpOptions['uplink-chunk-size'] || '').trim();
            const sessionPlacement = String(xhttpOptions['session-placement'] || '').trim();
            const sessionKey = String(xhttpOptions['session-key'] || '').trim();
            const seqPlacement = String(xhttpOptions['seq-placement'] || '').trim();
            const seqKey = String(xhttpOptions['seq-key'] || '').trim();
            const scMaxEachPostBytes = String(xhttpOptions['sc-max-each-post-bytes'] || '').trim();
            const scMinPostsIntervalMs = String(xhttpOptions['sc-min-posts-interval-ms'] ?? '').trim();
            const reuseMaxConcurrency = String(xhttpOptions['reuse-settings']?.['max-concurrency'] || '').trim();
            const reuseMaxConnections = String(xhttpOptions['reuse-settings']?.['max-connections'] || '').trim();
            const reuseCMaxReuseTimes = String(xhttpOptions['reuse-settings']?.['c-max-reuse-times'] || '').trim();
            const reuseHMaxRequestTimes = String(xhttpOptions['reuse-settings']?.['h-max-request-times'] || '').trim();
            const reuseHMaxReusableSecs = String(xhttpOptions['reuse-settings']?.['h-max-reusable-secs'] || '').trim();
            const reuseHKeepAlivePeriod = String(xhttpOptions['reuse-settings']?.['h-keep-alive-period'] ?? '').trim();
            let xhttpDownloadSettingsSource = xhttpOptions['download-settings'];
            let xhttpDownloadSettingsParseError = '';
            if (hasTextValue(proxy?._xhttpDownloadSettingsText)) {
                try {
                    xhttpDownloadSettingsSource = parseYamlObjectText(proxy._xhttpDownloadSettingsText);
                } catch (err) {
                    xhttpDownloadSettingsParseError = err && err.message ? err.message : '解析失败';
                }
            }
            const xhttpDownloadSettings = isPlainObject(xhttpDownloadSettingsSource) ? xhttpDownloadSettingsSource : {};
            const unsupportedXhttpDownloadSettingsKeys = collectUnsupportedXhttpDownloadSettingsKeys(xhttpDownloadSettings);
            const alpnValues = parseScalarListText(parsed.alpn).map((item) => item.toLowerCase());
            const pushToggleIssue = (enabled, toggle, label, tcpOnlyMessage) => {
                if (!enabled) return;
                if (!caps.toggles[toggle]) {
                    issues.push({
                        level: 'error',
                        message: `${parsed.type} 当前不支持 ${label}。`
                    });
                    return;
                }
                if (proxyToggleRequiresTcpNetwork(toggle) && supportsTransport && effectiveNetwork !== 'tcp') {
                    issues.push({
                        level: 'error',
                        message: tcpOnlyMessage
                    });
                }
            };

            if (supportsTransport && requestedNetwork && requestedNetwork !== effectiveNetwork) {
                issues.push({
                    level: 'error',
                    message: `${parsed.type} 不支持 ${requestedNetwork} 传输层，官方文档支持的默认值是 ${defaultNetwork}。`
                });
            }

            if (packetEncoding && !PACKET_ENCODING_OPTIONS.has(packetEncoding)) {
                issues.push({
                    level: 'error',
                    message: `packet-encoding 仅支持 ${Array.from(PACKET_ENCODING_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'vless' && !uuid) {
                issues.push({
                    level: 'error',
                    message: 'VLESS 缺少 uuid。'
                });
            }

            if (parsed.type === 'vless' && flow && !VLESS_FLOW_OPTIONS.has(flow)) {
                issues.push({
                    level: 'error',
                    message: `VLESS 的 flow 当前仅支持 ${Array.from(VLESS_FLOW_OPTIONS).join(' / ')}。`
                });
            } else if (parsed.type === 'vless' && flow && effectiveNetwork !== 'tcp') {
                issues.push({
                    level: 'error',
                    message: 'VLESS 的 flow 仅应与 TCP 传输层组合使用。'
                });
            } else if (parsed.type === 'vless' && flow && !caps.hasTlsSection) {
                issues.push({
                    level: 'error',
                    message: 'VLESS 启用 flow 时，需要同时启用 TLS 或 REALITY。'
                });
            }

            if (parsed.type === 'vmess' && !uuid) {
                issues.push({
                    level: 'error',
                    message: 'VMess 缺少 uuid。'
                });
            }

            if (parsed.type === 'vmess' && vmessCipher && !VMESS_CIPHER_OPTIONS.has(vmessCipher)) {
                issues.push({
                    level: 'error',
                    message: `VMess 的 cipher 仅支持 ${Array.from(VMESS_CIPHER_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'trojan' && !parsed.tls) {
                issues.push({
                    level: 'error',
                    message: 'Trojan 依赖 TLS，不能关闭 TLS。'
                });
            }

            if (parsed.type === 'trojan' && !password) {
                issues.push({
                    level: 'error',
                    message: 'Trojan 缺少 password。'
                });
            }

            if (parsed.type === 'trojan' && hasTrojanSsOpts && !trojanSsPassword) {
                issues.push({
                    level: 'error',
                    message: 'Trojan 启用 ss-opts 时，必须填写 AEAD password。'
                });
            }

            if (parsed.type === 'ss' && !ssCipher) {
                issues.push({
                    level: 'error',
                    message: 'Shadowsocks 缺少 cipher。'
                });
            }

            if (parsed.type === 'ss' && !password) {
                issues.push({
                    level: 'error',
                    message: 'Shadowsocks 缺少 password。'
                });
            }

            if (parsed.type === 'ss' && parsed['udp-over-tcp'] && ![1, 2].includes(Number(parsed['udp-over-tcp-version']))) {
                issues.push({
                    level: 'error',
                    message: 'Shadowsocks 的 udp-over-tcp-version 仅支持 1 或 2。'
                });
            }

            if (parsed.type === 'ssr' && !ssCipher) {
                issues.push({
                    level: 'error',
                    message: 'ShadowsocksR 缺少 cipher。'
                });
            }

            if (parsed.type === 'ssr' && !password) {
                issues.push({
                    level: 'error',
                    message: 'ShadowsocksR 缺少 password。'
                });
            }

            if (parsed.type === 'ssr' && !String(parsed.protocol || '').trim()) {
                issues.push({
                    level: 'error',
                    message: 'ShadowsocksR 缺少 protocol。'
                });
            }

            if (parsed.type === 'ssr' && !String(parsed.obfs || '').trim()) {
                issues.push({
                    level: 'error',
                    message: 'ShadowsocksR 缺少 obfs。'
                });
            }

            if (parsed.type === 'hysteria' && !password) {
                issues.push({
                    level: 'error',
                    message: 'Hysteria 缺少 auth-str。'
                });
            }

            if (parsed.type === 'hysteria' && hysteriaProtocol && !HYSTERIA_PROTOCOL_OPTIONS.has(hysteriaProtocol)) {
                issues.push({
                    level: 'error',
                    message: `Hysteria 的 protocol 仅支持 ${Array.from(HYSTERIA_PROTOCOL_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'hysteria2' && !password) {
                issues.push({
                    level: 'error',
                    message: 'Hysteria2 缺少 password。'
                });
            }

            if (parsed.type === 'hysteria2' && hysteria2Obfs && !HYSTERIA2_OBFS_OPTIONS.has(hysteria2Obfs)) {
                issues.push({
                    level: 'error',
                    message: `Hysteria2 的 obfs 当前仅支持 ${Array.from(HYSTERIA2_OBFS_OPTIONS).join(' / ')}。`
                });
            } else if (parsed.type === 'hysteria2' && hysteria2Obfs && !String(parsed['obfs-password'] || '').trim()) {
                issues.push({
                    level: 'error',
                    message: 'Hysteria2 启用 obfs 时，必须填写 obfs-password。'
                });
            } else if (parsed.type === 'hysteria2' && hysteria2Obfs === 'gecko') {
                const minPacket = Number(parsed['obfs-min-packet-size']);
                const maxPacket = Number(parsed['obfs-max-packet-size']);
                if (String(parsed['obfs-min-packet-size'] || '').trim() && (!Number.isInteger(minPacket) || minPacket <= 0)) {
                    issues.push({
                        level: 'error',
                        message: 'Hysteria2 gecko 的 obfs-min-packet-size 必须是正整数。'
                    });
                }
                if (String(parsed['obfs-max-packet-size'] || '').trim() && (!Number.isInteger(maxPacket) || maxPacket <= 0)) {
                    issues.push({
                        level: 'error',
                        message: 'Hysteria2 gecko 的 obfs-max-packet-size 必须是正整数。'
                    });
                }
                if (Number.isInteger(minPacket) && Number.isInteger(maxPacket) && minPacket > 0 && maxPacket > 0 && minPacket > maxPacket) {
                    issues.push({
                        level: 'error',
                        message: 'Hysteria2 gecko 的 obfs-min-packet-size 不能大于 obfs-max-packet-size。'
                    });
                }
            }

            if (parsed.type === 'hysteria2' && hy2Ports && !isValidPortRangeListText(hy2Ports)) {
                issues.push({
                    level: 'error',
                    message: 'Hysteria2 的 ports 必须使用有效端口范围语法，例如 40000-50000,60000/60010-60020。'
                });
            }

            if (parsed.type === 'hysteria2' && hy2HopInterval && !isValidHy2HopIntervalText(hy2HopInterval)) {
                issues.push({
                    level: 'error',
                    message: 'Hysteria2 的 hop-interval 必须是正整数秒值或范围，例如 30 或 15-30。'
                });
            } else if (parsed.type === 'hysteria2' && hy2HopInterval && !hy2Ports) {
                issues.push({
                    level: 'warning',
                    message: 'Hysteria2 的 hop-interval 仅在配置 ports 端口跳跃时生效。'
                });
            }

            if (parsed.type === 'hysteria2' && bbrProfile && !BBR_PROFILE_OPTIONS.has(bbrProfile)) {
                issues.push({
                    level: 'error',
                    message: `Hysteria2 的 bbr-profile 仅支持 ${Array.from(BBR_PROFILE_OPTIONS).join(' / ')}。`
                });
            }

            if (caps.features.tuicProfile) {
                const hasToken = token.length > 0;
                const hasUuid = uuid.length > 0;
                const hasPassword = password.length > 0;
                if (hasToken && (hasUuid || hasPassword)) {
                    issues.push({
                        level: 'error',
                        message: 'TUIC 应使用 token 或 uuid+password 二选一，不应同时填写。'
                    });
                } else if (!hasToken && !(hasUuid && hasPassword)) {
                    issues.push({
                        level: 'error',
                        message: 'TUIC 需要填写 token，或同时填写 uuid 与 password。'
                    });
                }

                if (tuicUdpRelayMode && !TUIC_UDP_RELAY_MODE_OPTIONS.has(tuicUdpRelayMode)) {
                    issues.push({
                        level: 'error',
                        message: `TUIC 的 udp-relay-mode 仅支持 ${Array.from(TUIC_UDP_RELAY_MODE_OPTIONS).join(' / ')}。`
                    });
                }

                if (congestionController && !QUIC_CONGESTION_CONTROLLER_OPTIONS.has(congestionController)) {
                    issues.push({
                        level: 'error',
                        message: `TUIC 的 congestion-controller 仅支持 ${Array.from(QUIC_CONGESTION_CONTROLLER_OPTIONS).join(' / ')}。`
                    });
                }
            }

            if (caps.features.wireguardProfile && !privateKey) {
                issues.push({
                    level: 'error',
                    message: 'WireGuard 缺少 private-key。'
                });
            }

            if (caps.features.wireguardProfile && !publicKey) {
                issues.push({
                    level: 'error',
                    message: 'WireGuard 缺少 public-key。'
                });
            }

            if (caps.features.wireguardProfile && !ipAddress) {
                issues.push({
                    level: 'error',
                    message: 'WireGuard 缺少本地 IP 地址。'
                });
            } else if (caps.features.wireguardProfile && parsed['remote-dns-resolve'] && dnsEntries.length === 0) {
                issues.push({
                    level: 'warning',
                    message: 'WireGuard 开启 remote-dns-resolve 后，建议同时填写 dns。'
                });
            }

            if (caps.features.masqueProfile && !privateKey) {
                issues.push({
                    level: 'error',
                    message: 'MASQUE 缺少 private-key。'
                });
            }

            if (caps.features.masqueProfile && !publicKey) {
                issues.push({
                    level: 'error',
                    message: 'MASQUE 缺少 public-key。'
                });
            }

            if (caps.features.masqueProfile && !ipAddress) {
                issues.push({
                    level: 'error',
                    message: 'MASQUE 缺少本地 IP 地址。'
                });
            } else if (caps.features.masqueProfile && parsed['remote-dns-resolve'] && dnsEntries.length === 0) {
                issues.push({
                    level: 'warning',
                    message: 'MASQUE 开启 remote-dns-resolve 后，建议同时填写 dns。'
                });
            }

            if (caps.features.masqueProfile && congestionController && effectiveNetwork !== 'quic') {
                issues.push({
                    level: 'warning',
                    message: 'MASQUE 的 congestion-controller 仅在 QUIC 传输层下生效；当前 H2 模式会忽略它。'
                });
            } else if (caps.features.masqueProfile && congestionController && !MASQUE_CONGESTION_CONTROLLER_OPTIONS.has(congestionController)) {
                issues.push({
                    level: 'error',
                    message: `MASQUE 的 congestion-controller 官方当前仅列出 ${Array.from(MASQUE_CONGESTION_CONTROLLER_OPTIONS).join(' / ')}。`
                });
            }

            if (caps.features.masqueProfile && bbrProfile && effectiveNetwork !== 'quic') {
                issues.push({
                    level: 'warning',
                    message: 'MASQUE 的 bbr-profile 仅在 QUIC 传输层下生效。'
                });
            } else if (caps.features.masqueProfile && bbrProfile && !BBR_PROFILE_OPTIONS.has(bbrProfile)) {
                issues.push({
                    level: 'error',
                    message: `MASQUE 的 bbr-profile 仅支持 ${Array.from(BBR_PROFILE_OPTIONS).join(' / ')}。`
                });
            }

            if (caps.features.sshProfile && !username) {
                issues.push({
                    level: 'error',
                    message: 'SSH 缺少 username。'
                });
            }

            if (caps.features.sshProfile && !sshHasPassword && !sshHasPrivateKey) {
                issues.push({
                    level: 'error',
                    message: 'SSH 至少需要填写 password 或 private-key。'
                });
            } else if (caps.features.sshProfile && sshPrivateKeyPassphrase && !sshHasPrivateKey) {
                issues.push({
                    level: 'warning',
                    message: 'SSH 仅在填写 private-key 时，private-key-passphrase 才会生效。'
                });
            }

            if (parsed.type === 'snell' && !password) {
                issues.push({
                    level: 'error',
                    message: 'Snell 缺少 PSK。'
                });
            }

            if (parsed.type === 'snell' && snellVersion && !SNELL_VERSION_OPTIONS.has(snellVersion)) {
                issues.push({
                    level: 'error',
                    message: `Snell 的 version 仅支持 ${Array.from(SNELL_VERSION_OPTIONS).join(' / ')}。`
                });
            } else if (parsed.type === 'snell' && parsed.udp && !SNELL_UDP_VERSION_OPTIONS.has(snellVersion)) {
                issues.push({
                    level: 'error',
                    message: 'Snell 仅在 version 3 / 4 / 5 时支持 UDP；留空会使用官方默认 version 1。'
                });
            }

            if (parsed.type === 'snell' && parsed.reuse && !['4', '5'].includes(snellVersion)) {
                issues.push({
                    level: 'warning',
                    message: 'Snell 的 reuse 仅在 version 4 / 5 时生效。'
                });
            }

            if (parsed.type === 'anytls' && !password) {
                issues.push({
                    level: 'error',
                    message: 'AnyTLS 缺少 password。'
                });
            }

            if (caps.features.mieruProfile && !username) {
                issues.push({
                    level: 'error',
                    message: 'Mieru 缺少 username。'
                });
            }

            if (caps.features.mieruProfile && !password) {
                issues.push({
                    level: 'error',
                    message: 'Mieru 缺少 password。'
                });
            }

            if (caps.features.mieruProfile && hasMieruPortRange && String(parsed.port || '').trim()) {
                issues.push({
                    level: 'error',
                    message: 'Mieru 的 port-range 不能与 port 同时使用。'
                });
            }

            if (caps.features.mieruProfile && mieruTransport && !MIERU_TRANSPORT_OPTIONS.has(mieruTransport)) {
                issues.push({
                    level: 'error',
                    message: `Mieru 的 transport 仅支持 ${Array.from(MIERU_TRANSPORT_OPTIONS).join(' / ')}。`
                });
            }

            if (caps.features.mieruProfile && mieruMultiplexing && !MIERU_MULTIPLEXING_OPTIONS.has(mieruMultiplexing)) {
                issues.push({
                    level: 'error',
                    message: `Mieru 的 multiplexing 仅支持 ${Array.from(MIERU_MULTIPLEXING_OPTIONS).join(' / ')}。`
                });
            }

            if (caps.features.trustTunnelProfile && !username) {
                issues.push({
                    level: 'error',
                    message: 'TrustTunnel 缺少 username。'
                });
            }

            if (caps.features.trustTunnelProfile && !password) {
                issues.push({
                    level: 'error',
                    message: 'TrustTunnel 缺少 password。'
                });
            }

            if (caps.features.trustTunnelProfile && parsed.quic && congestionController && !QUIC_CONGESTION_CONTROLLER_OPTIONS.has(congestionController)) {
                issues.push({
                    level: 'error',
                    message: `TrustTunnel 的 congestion-controller 仅支持 ${Array.from(QUIC_CONGESTION_CONTROLLER_OPTIONS).join(' / ')}。`
                });
            }

            if (caps.features.trustTunnelProfile && bbrProfile && !BBR_PROFILE_OPTIONS.has(bbrProfile)) {
                issues.push({
                    level: 'error',
                    message: `TrustTunnel 的 bbr-profile 仅支持 ${Array.from(BBR_PROFILE_OPTIONS).join(' / ')}。`
                });
            }

            if (caps.features.openvpnProfile) {
                if (openvpnProto && !OPENVPN_PROTO_OPTIONS.has(openvpnProto)) {
                    issues.push({
                        level: 'error',
                        message: `OpenVPN 的 proto 仅支持 ${Array.from(OPENVPN_PROTO_OPTIONS).join(' / ')}。`
                    });
                }
                if (openvpnDev && !OPENVPN_DEV_OPTIONS.has(openvpnDev)) {
                    issues.push({
                        level: 'error',
                        message: 'OpenVPN 当前仅支持 dev=tun。'
                    });
                }
                if (openvpnCipher && !OPENVPN_CIPHER_OPTIONS.has(openvpnCipher)) {
                    issues.push({
                        level: 'error',
                        message: `OpenVPN 的 cipher 仅支持 ${Array.from(OPENVPN_CIPHER_OPTIONS).join(' / ')}。`
                    });
                }
                if (openvpnAuth && !OPENVPN_AUTH_OPTIONS.has(openvpnAuth)) {
                    issues.push({
                        level: 'error',
                        message: `OpenVPN 的 auth 仅支持 ${Array.from(OPENVPN_AUTH_OPTIONS).join(' / ')}。`
                    });
                }
                if (openvpnCompLzo && !OPENVPN_COMP_LZO_OPTIONS.has(openvpnCompLzo)) {
                    issues.push({
                        level: 'error',
                        message: `OpenVPN 的 comp-lzo 仅支持 ${Array.from(OPENVPN_COMP_LZO_OPTIONS).join(' / ')}。`
                    });
                }
                if (!openvpnCa) {
                    issues.push({
                        level: 'error',
                        message: 'OpenVPN 缺少 ca PEM 内容。'
                    });
                } else if (!/-----BEGIN CERTIFICATE-----/.test(openvpnCa)) {
                    issues.push({
                        level: 'warning',
                        message: 'OpenVPN 的 ca 通常需要填写 .ovpn 中 <ca>...</ca> 内的 PEM 证书内容。'
                    });
                }
                if ((openvpnCert && !openvpnKey) || (!openvpnCert && openvpnKey)) {
                    issues.push({
                        level: 'error',
                        message: 'OpenVPN 使用证书认证时 cert 和 key 必须同时填写。'
                    });
                }
                if (!openvpnUsername && !(openvpnCert && openvpnKey)) {
                    issues.push({
                        level: 'error',
                        message: 'OpenVPN 需要 username/password 认证，或同时填写 cert 与 key。'
                    });
                }
                if (openvpnPing && !isValidIntegerText(openvpnPing, { min: 0 })) {
                    issues.push({
                        level: 'error',
                        message: 'OpenVPN 的 ping 必须是大于等于 0 的整数秒值。'
                    });
                }
                if (openvpnPingRestart && !isValidIntegerText(openvpnPingRestart, { min: 0 })) {
                    issues.push({
                        level: 'error',
                        message: 'OpenVPN 的 ping-restart 必须是大于等于 0 的整数秒值。'
                    });
                }
                if (openvpnMtu && !isValidIntegerText(openvpnMtu, { min: 1 })) {
                    issues.push({
                        level: 'error',
                        message: 'OpenVPN 的 mtu 必须是正整数。'
                    });
                }
                if (parsed['remote-dns-resolve'] && dnsEntries.length === 0) {
                    issues.push({
                        level: 'warning',
                        message: 'OpenVPN 开启 remote-dns-resolve 后，建议同时填写 dns。'
                    });
                }
            }

            if (realityEnabled && !caps.toggles.reality) {
                issues.push({
                    level: 'error',
                    message: `${parsed.type} 不支持 REALITY，官方文档当前仅列出 VLESS、VMess、Trojan。`
                });
            }

            pushToggleIssue(!!parsed.tfo, 'tfo', 'TFO', 'TFO 只应与 TCP 传输层组合使用。');
            pushToggleIssue(!!parsed.mptcp, 'mptcp', 'MPTCP', 'MPTCP 只应与 TCP 传输层组合使用。');

            if (realityEnabled && !realityPublicKey) {
                issues.push({
                    level: 'error',
                    message: 'REALITY 已启用，但缺少 public-key。'
                });
            }

            pushToggleIssue(smuxEnabled, 'smux', 'SMUX', 'SMUX 只应与 TCP 传输层组合使用。');

            if (smuxEnabled && smuxMaxConnections > 0 && smuxMaxStreams > 0 && smuxMaxConnections !== defaultSmuxMaxConnections) {
                issues.push({
                    level: 'warning',
                    message: 'SMUX 的 max-connections 与 max-streams 不能同时设置。'
                });
            }

            if (smuxEnabled && smuxMinStreams > 0 && smuxMaxStreams > 0) {
                issues.push({
                    level: 'warning',
                    message: 'SMUX 的 min-streams 与 max-streams 不能同时设置。'
                });
            }

            if (smuxEnabled && brutalEnabled && (!String(smux['brutal-opts']?.up || '').trim() || !String(smux['brutal-opts']?.down || '').trim())) {
                issues.push({
                    level: 'warning',
                    message: 'SMUX Brutal 模式需要同时填写 up 和 down。'
                });
            }

            if (effectiveNetwork === 'grpc' && grpcMaxConnections > 0 && grpcMaxStreams > 0 && grpcMaxConnections !== defaultGrpcMaxConnections) {
                issues.push({
                    level: 'warning',
                    message: 'gRPC 的 max-connections 与 max-streams 不能同时设置。'
                });
            }

            if (effectiveNetwork === 'grpc' && grpcMinStreams > 0 && grpcMaxStreams > 0) {
                issues.push({
                    level: 'warning',
                    message: 'gRPC 的 min-streams 与 max-streams 不能同时设置。'
                });
            }

            if (caps.features.trustTunnelProfile && !parsed.quic && (trustTunnelMaxConnections > 0 || trustTunnelMinStreams > 0 || trustTunnelMaxStreams > 0)) {
                issues.push({
                    level: 'warning',
                    message: 'TrustTunnel 的 max-connections / min-streams / max-streams 仅在启用 QUIC 时生效。'
                });
            }

            if (caps.features.trustTunnelProfile && parsed.quic && trustTunnelMaxConnections > 0 && trustTunnelMaxStreams > 0) {
                issues.push({
                    level: 'warning',
                    message: 'TrustTunnel 的 max-connections 与 max-streams 不能同时设置。'
                });
            }

            if (caps.features.trustTunnelProfile && parsed.quic && trustTunnelMinStreams > 0 && trustTunnelMaxStreams > 0) {
                issues.push({
                    level: 'warning',
                    message: 'TrustTunnel 的 min-streams 与 max-streams 不能同时设置。'
                });
            }

            if (effectiveNetwork === 'ws' && wsHttpUpgradeFastOpenEnabled && !wsHttpUpgradeEnabled) {
                issues.push({
                    level: 'warning',
                    message: 'WebSocket 的 v2ray-http-upgrade-fast-open 仅在启用 v2ray-http-upgrade 时生效。'
                });
            }

            if (effectiveNetwork === 'xhttp' && sessionPlacement === 'path' && seqPlacement && seqPlacement !== 'path') {
                issues.push({
                    level: 'error',
                    message: 'xHTTP 的 seq-placement 在 session-placement 为 path 时必须同为 path。'
                });
            }

            if (effectiveNetwork === 'xhttp' && xhttpMode && !XHTTP_MODE_OPTIONS.has(xhttpMode)) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 mode 仅支持 ${Array.from(XHTTP_MODE_OPTIONS).join(' / ')}。`
                });
            }

            if (effectiveNetwork === 'xhttp' && xPaddingPlacement && !XHTTP_PADDING_PLACEMENT_OPTIONS.has(xPaddingPlacement)) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 x-padding-placement 仅支持 ${Array.from(XHTTP_PADDING_PLACEMENT_OPTIONS).join(' / ')}。`
                });
            }

            if (effectiveNetwork === 'xhttp' && xPaddingMethod && !XHTTP_PADDING_METHOD_OPTIONS.has(xPaddingMethod)) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 x-padding-method 仅支持 ${Array.from(XHTTP_PADDING_METHOD_OPTIONS).join(' / ')}。`
                });
            }

            if (effectiveNetwork === 'xhttp' && xPaddingBytes && !isValidPositiveIntegerOrRangeText(xPaddingBytes)) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP 的 x-padding-bytes 必须是正整数或范围，例如 100 或 100-1000。'
                });
            }

            if (effectiveNetwork === 'xhttp' && uplinkHttpMethod && !XHTTP_UPLINK_HTTP_METHOD_OPTIONS.has(uplinkHttpMethod)) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 uplink-http-method 仅支持 ${Array.from(XHTTP_UPLINK_HTTP_METHOD_OPTIONS).join(' / ')}。`
                });
            }

            if (effectiveNetwork === 'xhttp' && uplinkDataPlacement && !XHTTP_UPLINK_DATA_PLACEMENT_OPTIONS.has(uplinkDataPlacement)) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 uplink-data-placement 仅支持 ${Array.from(XHTTP_UPLINK_DATA_PLACEMENT_OPTIONS).join(' / ')}。`
                });
            }

            if (effectiveNetwork === 'xhttp' && sessionPlacement && !XHTTP_KEY_PLACEMENT_OPTIONS.has(sessionPlacement)) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 session-placement 仅支持 ${Array.from(XHTTP_KEY_PLACEMENT_OPTIONS).join(' / ')}。`
                });
            }

            if (effectiveNetwork === 'xhttp' && seqPlacement && !XHTTP_KEY_PLACEMENT_OPTIONS.has(seqPlacement)) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 seq-placement 仅支持 ${Array.from(XHTTP_KEY_PLACEMENT_OPTIONS).join(' / ')}。`
                });
            }

            if (effectiveNetwork === 'xhttp' && xhttpMode === 'packet-up' && xhttpOptions['no-grpc-header']) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 的 no-grpc-header 仅在 stream-one / stream-up 模式下生效。'
                });
            }

            if (effectiveNetwork === 'xhttp' && sessionPlacement === 'path' && sessionKey) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 的 session-key 在 session-placement=path 时不会生效。'
                });
            }

            if (effectiveNetwork === 'xhttp' && seqPlacement === 'path' && seqKey) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 的 seq-key 在 seq-placement=path 时不会生效。'
                });
            }

            if (effectiveNetwork === 'xhttp' && (uplinkDataPlacement || uplinkDataKey || uplinkChunkSize) && xhttpMode !== 'packet-up') {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 的 uplink-data-* 参数仅在 packet-up 模式下生效。'
                });
            }

            if (effectiveNetwork === 'xhttp' && uplinkChunkSize && uplinkDataPlacement === 'body') {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 的 uplink-chunk-size 在 uplink-data-placement=body 时不会生效。'
                });
            } else if (effectiveNetwork === 'xhttp' && uplinkChunkSize && !isValidIntegerText(uplinkChunkSize, { min: 64 })) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP 的 uplink-chunk-size 必须是大于等于 64 的整数。'
                });
            }

            if (effectiveNetwork === 'xhttp' && reuseMaxConcurrency && reuseMaxConnections) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP XMUX 的 max-concurrency 与 max-connections 不能同时设置。'
                });
            }

            if (effectiveNetwork === 'xhttp' && reuseMaxConcurrency && !isValidPositiveIntegerOrRangeText(reuseMaxConcurrency)) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP XMUX 的 max-concurrency 必须是正整数或范围，例如 16 或 16-32。'
                });
            }

            if (effectiveNetwork === 'xhttp' && reuseMaxConnections && !isValidIntegerText(reuseMaxConnections, { min: 0 })) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP XMUX 的 max-connections 必须是大于等于 0 的整数。'
                });
            }

            if (effectiveNetwork === 'xhttp' && reuseCMaxReuseTimes && !isValidIntegerText(reuseCMaxReuseTimes, { min: 0 })) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP XMUX 的 c-max-reuse-times 必须是大于等于 0 的整数。'
                });
            }

            if (effectiveNetwork === 'xhttp' && reuseHMaxRequestTimes && !isValidPositiveIntegerOrRangeText(reuseHMaxRequestTimes)) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP XMUX 的 h-max-request-times 必须是正整数或范围，例如 600 或 600-900。'
                });
            }

            if (effectiveNetwork === 'xhttp' && reuseHMaxReusableSecs && !isValidPositiveIntegerOrRangeText(reuseHMaxReusableSecs)) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP XMUX 的 h-max-reusable-secs 必须是正整数或范围，例如 1800 或 1800-3000。'
                });
            }

            if (effectiveNetwork === 'xhttp' && reuseHKeepAlivePeriod && !isValidIntegerText(reuseHKeepAlivePeriod, { allowNegative: true })) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP XMUX 的 h-keep-alive-period 必须是整数，可为 -1。'
                });
            }

            if (effectiveNetwork === 'xhttp' && (xPaddingPlacement || xPaddingHeader || xPaddingKey || xPaddingMethod) && !xPaddingObfsMode) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 的 x-padding-* 细项仅在启用 x-padding-obfs-mode 时生效。'
                });
            }

            if (effectiveNetwork === 'xhttp' && xPaddingObfsMode && ['header', 'queryInHeader'].includes(xPaddingPlacement) && !xPaddingHeader) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 在 header / queryInHeader 放置填充时，建议同时填写 x-padding-header。'
                });
            }

            if (effectiveNetwork === 'xhttp' && xPaddingHeader && xPaddingPlacement && !['header', 'queryInHeader'].includes(xPaddingPlacement)) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 的 x-padding-header 仅在 x-padding-placement 为 header 或 queryInHeader 时生效。'
                });
            }

            if (effectiveNetwork === 'xhttp' && alpnValues.length > 0 && !alpnValues.some((item) => ['h2', 'h3', 'http/1.1'].includes(item))) {
                issues.push({
                    level: 'warning',
                    message: 'xHTTP 通常应配合 h2 / h3 / http/1.1 的 ALPN；当前值可能无法按官方示例工作。'
                });
            }

            if (effectiveNetwork === 'xhttp' && scMaxEachPostBytes && !isValidIntegerText(scMaxEachPostBytes, { min: 1 })) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP 的 sc-max-each-post-bytes 必须是正整数。'
                });
            }

            if (effectiveNetwork === 'xhttp' && scMinPostsIntervalMs && !isValidIntegerText(scMinPostsIntervalMs, { min: 0 })) {
                issues.push({
                    level: 'error',
                    message: 'xHTTP 的 sc-min-posts-interval-ms 必须是大于等于 0 的整数。'
                });
            }

            if (effectiveNetwork === 'xhttp' && xhttpDownloadSettingsParseError) {
                issues.push({
                    level: 'error',
                    message: `xHTTP 的 download-settings 不是有效 YAML/JSON：${xhttpDownloadSettingsParseError}`
                });
            }

            if (effectiveNetwork === 'xhttp' && unsupportedXhttpDownloadSettingsKeys.length > 0) {
                issues.push({
                    level: 'warning',
                    message: `xHTTP 的 download-settings 仅会覆盖官方列出的字段；以下键会被忽略：${unsupportedXhttpDownloadSettingsKeys.join('、')}。`
                });
            }

            if (parsed.type === 'tuic' && bbrProfile && !BBR_PROFILE_OPTIONS.has(bbrProfile)) {
                issues.push({
                    level: 'error',
                    message: `TUIC 的 bbr-profile 仅支持 ${Array.from(BBR_PROFILE_OPTIONS).join(' / ')}。`
                });
            } else if (['tuic', 'trusttunnel'].includes(parsed.type) && bbrProfile && hasTextValue(congestionController) && congestionController !== 'bbr') {
                issues.push({
                    level: 'warning',
                    message: `${parsed.type} 的 bbr-profile 仅在 congestion-controller 为 bbr 时生效。`
                });
            }

            if (clientFingerprint && !caps.supportsTlsClientFingerprint) {
                issues.push({
                    level: 'warning',
                    message: `${parsed.type} 的官方页面没有列出 client-fingerprint，导出时会忽略它。`
                });
            }

            if (fingerprint && !caps.hasTlsSection) {
                issues.push({
                    level: 'warning',
                    message: '证书指纹只会在启用 TLS 或协议自带 TLS 时生效。'
                });
            } else if (fingerprint && !serverName && caps.tlsServerNameKey) {
                issues.push({
                    level: 'warning',
                    message: '设置证书指纹时，建议同时填写 Server Name / SNI，避免证书匹配异常。'
                });
            }

            return issues;
        };
        const sanitizeProxyNodeForYaml = (proxy) => {
            const parsed = parseSingleProxyNode(proxy);
            if (!parsed) return null;
            const defaults = parseSingleProxyNode({ type: parsed.type });
            const next = compactWithDefaults(parsed, defaults, new Set(['name', 'type', 'server', 'port'])) || {};
            const caps = resolveProxyCapabilities(proxy);
            const { type, tlsMode, hasTlsSection, supportsTlsClientFingerprint, defaultNetwork, effectiveNetwork, features, tlsServerNameKey } = caps;
            if (tlsMode === 'required') next.tls = true;
            else if (tlsMode !== 'toggle') delete next.tls;
            const realityEnabled = !!proxy.reality;
            const echEnabled = !!proxy['ech-opts']?.enable;
            const smuxEnabled = !!proxy.smux?.enabled;
            const brutalEnabled = !!proxy.smux?.['brutal-opts']?.enabled;
            const obfsEnabled = !!String(proxy.obfs || '').trim();

            delete next.reality;
            if (effectiveNetwork === defaultNetwork) delete next.network;
            else next.network = effectiveNetwork;
            if (features.topLevelHeaders) {
                const proxyHeaders = parseYamlMapText(proxy._proxyHeadersText);
                if (proxyHeaders) next.headers = proxyHeaders;
                else delete next.headers;
            } else {
                delete next.headers;
            }
            if (!parsed.plugin) {
                delete next.plugin;
                delete next['plugin-opts'];
                delete next['kcptun-opts'];
            } else if (parsed.plugin !== 'kcptun') {
                delete next['kcptun-opts'];
            }
            if (effectiveNetwork === 'ws' && String(proxy._wsHeadersText || '').trim() && !next['ws-opts']) next['ws-opts'] = {};
            if (effectiveNetwork === 'http' && (String(proxy._httpHeadersText || '').trim() || String(proxy._httpPathsText || '').trim() || String(proxy['http-opts']?.host || '').trim()) && !next['http-opts']) next['http-opts'] = {};
            if (effectiveNetwork === 'xhttp' && (String(proxy._xhttpHeadersText || '').trim() || String(proxy._xhttpDownloadSettingsText || '').trim()) && !next['xhttp-opts']) next['xhttp-opts'] = {};
            if (effectiveNetwork === 'h2' && String(proxy._h2HostsText || '').trim() && !next['h2-opts']) next['h2-opts'] = {};
            if (next['ws-opts']) {
                const wsHeaders = parseYamlMapText(proxy._wsHeadersText);
                if (wsHeaders) next['ws-opts'].headers = wsHeaders;
                else delete next['ws-opts'].headers;
                if (!next['ws-opts']['v2ray-http-upgrade']) delete next['ws-opts']['v2ray-http-upgrade-fast-open'];
            }
            if (next['http-opts']) {
                const httpHeaders = parseYamlMapText(proxy._httpHeadersText);
                if (httpHeaders) next['http-opts'].headers = httpHeaders;
                else delete next['http-opts'].headers;
                const httpPaths = parseScalarListText(proxy._httpPathsText);
                if (httpPaths.length > 0) next['http-opts'].path = httpPaths;
                else delete next['http-opts'].path;
                const httpHost = String(proxy['http-opts']?.host || '').trim();
                if (httpHost) {
                    const hostList = parseScalarListText(httpHost);
                    if (hostList.length > 0) {
                        next['http-opts'].headers = next['http-opts'].headers || {};
                        next['http-opts'].headers.Host = hostList.length === 1 ? hostList[0] : hostList;
                    }
                }
                delete next['http-opts'].host;
            }
            if (next['xhttp-opts']) {
                const xhttpHeaders = parseYamlMapText(proxy._xhttpHeadersText);
                if (xhttpHeaders) next['xhttp-opts'].headers = xhttpHeaders;
                else delete next['xhttp-opts'].headers;
                const downloadSettings = sanitizeXhttpDownloadSettings(parseYamlObjectText(proxy._xhttpDownloadSettingsText));
                if (downloadSettings) next['xhttp-opts']['download-settings'] = downloadSettings;
                else delete next['xhttp-opts']['download-settings'];
                if (next['xhttp-opts'].mode !== 'packet-up') {
                    delete next['xhttp-opts']['uplink-data-placement'];
                    delete next['xhttp-opts']['uplink-data-key'];
                    delete next['xhttp-opts']['uplink-chunk-size'];
                } else {
                    delete next['xhttp-opts']['no-grpc-header'];
                }
                if (!next['xhttp-opts']['x-padding-obfs-mode']) {
                    delete next['xhttp-opts']['x-padding-key'];
                    delete next['xhttp-opts']['x-padding-header'];
                    delete next['xhttp-opts']['x-padding-placement'];
                    delete next['xhttp-opts']['x-padding-method'];
                }
                if (!['header', 'queryInHeader'].includes(next['xhttp-opts']['x-padding-placement'])) delete next['xhttp-opts']['x-padding-header'];
                if (next['xhttp-opts']['uplink-data-placement'] === 'body') delete next['xhttp-opts']['uplink-chunk-size'];
                if (next['xhttp-opts']['session-placement'] === 'path') delete next['xhttp-opts']['session-key'];
                if (next['xhttp-opts']['seq-placement'] === 'path') delete next['xhttp-opts']['seq-key'];
            }
            if (next['h2-opts']) {
                const h2Hosts = parseScalarListText(proxy._h2HostsText);
                if (h2Hosts.length > 0) next['h2-opts'].host = h2Hosts;
                else delete next['h2-opts'].host;
            }
            if (effectiveNetwork !== 'ws') delete next['ws-opts'];
            if (effectiveNetwork !== 'grpc') delete next['grpc-opts'];
            if (effectiveNetwork !== 'h2') delete next['h2-opts'];
            if (parsed.network !== 'httpupgrade') delete next['httpupgrade-opts'];
            if (effectiveNetwork !== 'http') delete next['http-opts'];
            if (effectiveNetwork !== 'xhttp') delete next['xhttp-opts'];
            if (!proxyToggleAvailableInCurrentNetwork(proxy, 'tfo')) delete next.tfo;
            if (!proxyToggleAvailableInCurrentNetwork(proxy, 'mptcp')) delete next.mptcp;
            if (!features.packetEncoding) delete next['packet-encoding'];
            if (!features.encryption) delete next.encryption;
            if (!features.vmessPadding) {
                delete next['global-padding'];
                delete next['authenticated-length'];
            }
            if (!features.trojanSsOpts || !proxy['ss-opts']?.enabled) delete next['ss-opts'];
            if (!features.udpOverTcpVersion || !proxy['udp-over-tcp']) delete next['udp-over-tcp-version'];
            if (!features.wireguardProfile && !features.openvpnProfile) {
                delete next.ipv6;
                delete next['allowed-ips'];
                delete next['persistent-keepalive'];
                delete next['remote-dns-resolve'];
                delete next.dns;
                delete next['amnezia-wg-option'];
            } else if (features.openvpnProfile) {
                delete next.ipv6;
                delete next['allowed-ips'];
                delete next['persistent-keepalive'];
                delete next['amnezia-wg-option'];
                delete next['wg-dns'];
            } else {
                const allowedIps = String(proxy['allowed-ips'] || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                if (allowedIps.length > 0) next['allowed-ips'] = allowedIps;
                else delete next['allowed-ips'];
                if (proxy['remote-dns-resolve']) {
                    const wireguardDns = String(proxy.dns || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                    if (wireguardDns.length > 0) next.dns = wireguardDns;
                    else delete next.dns;
                } else {
                    delete next.dns;
                }
                const amneziaWgOption = parseYamlObjectText(proxy._amneziaWgOptionText);
                if (amneziaWgOption) next['amnezia-wg-option'] = amneziaWgOption;
                else delete next['amnezia-wg-option'];
                delete next['wg-dns'];
            }
            if (!(features.wireguardProfile || features.masqueProfile || features.openvpnProfile)) {
                delete next.ip;
                delete next.ipv6;
                delete next['remote-dns-resolve'];
                delete next.dns;
            } else if (features.openvpnProfile) {
                delete next.ip;
                delete next.ipv6;
                if (proxy['remote-dns-resolve']) {
                    next['remote-dns-resolve'] = true;
                    const openvpnDns = String(proxy.dns || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                    if (openvpnDns.length > 0) next.dns = openvpnDns;
                    else delete next.dns;
                } else {
                    delete next['remote-dns-resolve'];
                    delete next.dns;
                }
            } else if (features.masqueProfile && proxy['remote-dns-resolve']) {
                next['remote-dns-resolve'] = true;
                const masqueDns = String(proxy.dns || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                if (masqueDns.length > 0) next.dns = masqueDns;
                else delete next.dns;
            } else if (features.masqueProfile) {
                delete next['remote-dns-resolve'];
                delete next.dns;
            }
            if (features.masqueProfile && effectiveNetwork !== 'quic') {
                delete next['congestion-controller'];
                delete next['bbr-profile'];
            }
            if (features.tuicProfile && next['congestion-controller'] && next['congestion-controller'] !== 'bbr') delete next['bbr-profile'];
            if (!features.tuicProfile) {
                delete next.token;
                delete next['heartbeat-interval'];
                delete next['disable-sni'];
                delete next['max-udp-relay-packet-size'];
                delete next['max-open-streams'];
            }
            if (!features.recvWindow) {
                delete next['recv-window-conn'];
                delete next['recv-window'];
                delete next.disable_mtu_discovery;
            }
            if (!features.fastOpen) delete next['fast-open'];
            if (!features.bbrProfile) delete next['bbr-profile'];
            if (!features.hysteria2Ports) {
                delete next.ports;
                delete next['hop-interval'];
            } else if (!String(proxy.ports || '').trim()) {
                delete next['hop-interval'];
            }
            if (!features.sshProfile) {
                delete next['private-key-passphrase'];
                delete next['host-key'];
                delete next['host-key-algorithms'];
            } else {
                const hostKey = String(proxy['host-key'] || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
                const hostKeyAlgorithms = String(proxy['host-key-algorithms'] || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
                if (hostKey.length > 0) next['host-key'] = hostKey;
                else delete next['host-key'];
                if (hostKeyAlgorithms.length > 0) next['host-key-algorithms'] = hostKeyAlgorithms;
                else delete next['host-key-algorithms'];
            }
            if (!features.mieruProfile) {
                delete next['port-range'];
                delete next['traffic-pattern'];
                delete next.transport;
                delete next.multiplexing;
            }
            if (!features.trustTunnelProfile) {
                delete next.quic;
                delete next['max-connections'];
                delete next['min-streams'];
                delete next['max-streams'];
            } else if (!proxy.quic) {
                delete next['congestion-controller'];
                delete next['max-connections'];
                delete next['min-streams'];
                delete next['max-streams'];
                delete next['bbr-profile'];
            } else if (next['congestion-controller'] && next['congestion-controller'] !== 'bbr') {
                delete next['bbr-profile'];
            }
            if (!features.sudokuProfile) {
                if (!features.openvpnProfile) delete next.key;
                delete next['aead-method'];
                delete next['padding-min'];
                delete next['padding-max'];
                delete next['table-type'];
                delete next['custom-table'];
                delete next['custom-tables'];
                delete next.httpmask;
                delete next['enable-pure-downlink'];
            } else {
                const customTables = String(proxy['custom-tables'] || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
                if (customTables.length > 0) next['custom-tables'] = customTables;
                else delete next['custom-tables'];
                const httpmask = parseYamlObjectText(proxy._sudokuHttpmaskText);
                if (httpmask) next.httpmask = httpmask;
                else delete next.httpmask;
            }
            if (!features.openvpnProfile) {
                delete next.proto;
                delete next.dev;
                delete next.auth;
                delete next['comp-lzo'];
                delete next.ca;
                delete next.cert;
                delete next['tls-crypt'];
                delete next.ping;
                delete next['ping-restart'];
            }
            if (parsed.type !== 'snell') {
                delete next.reuse;
            } else if (!['4', '5'].includes(String(parsed.version || '').trim())) {
                delete next.reuse;
            }
            if (!obfsEnabled) {
                delete next['obfs-password'];
                delete next['obfs-min-packet-size'];
                delete next['obfs-max-packet-size'];
                delete next['obfs-host'];
                delete next['obfs-param'];
            } else if (parsed.type !== 'hysteria2' || parsed.obfs !== 'gecko') {
                delete next['obfs-min-packet-size'];
                delete next['obfs-max-packet-size'];
            }
            if (features.passwordAlias === 'auth-str' && next.password) {
                next['auth-str'] = next.password;
                delete next.password;
            } else if (features.passwordAlias === 'psk' && next.password) {
                next.psk = next.password;
                delete next.password;
            }
            if (!realityEnabled || !caps.toggles.reality) delete next['reality-opts'];
            if (!hasTlsSection) {
                delete next.servername;
                delete next.sni;
                delete next.certificate;
                delete next.fingerprint;
                delete next['client-fingerprint'];
                delete next.alpn;
                delete next['skip-cert-verify'];
                delete next['ech-opts'];
                if (['toggle', 'required'].includes(tlsMode)) delete next['private-key'];
            } else {
                const serverNameValue = getProxyTlsServerNameValue(proxy);
                delete next.servername;
                delete next.sni;
                if (tlsServerNameKey && serverNameValue) next[tlsServerNameKey] = serverNameValue;
                if (!supportsTlsClientFingerprint) delete next['client-fingerprint'];
            }
            if (!echEnabled) delete next['ech-opts'];
            if (!smuxEnabled || !proxyToggleAvailableInCurrentNetwork(proxy, 'smux')) delete next.smux;
            if (next.smux && !brutalEnabled) delete next.smux['brutal-opts'];
            if (next['xhttp-opts'] && !Object.keys(next['xhttp-opts']['reuse-settings'] || {}).length) delete next['xhttp-opts']['reuse-settings'];
            if (next['xhttp-opts'] && !Object.keys(next['xhttp-opts']['download-settings'] || {}).length) delete next['xhttp-opts']['download-settings'];

            return pruneEmptyYamlValue(next);
        };

        return {
            parseSingleProxyNode,
            sanitizeProxyNodeForYaml,
            getProxyNetworkOptions,
            proxySupportsTransport,
            proxySupportsToggle,
            resolveProxyCapabilities,
            sanitizeProxyByCapabilities,
            proxyHasTlsSection,
            proxySupportsTlsClientFingerprint,
            getProxyValidationIssues,
            getProxyTlsMode
        };
    };
})(window);
