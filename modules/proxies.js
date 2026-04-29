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
        const PROXY_NETWORK_OPTIONS_MAP = {
            vless: [
                { value: 'tcp', label: 'TCP' },
                { value: 'ws', label: 'WebSocket' },
                { value: 'grpc', label: 'gRPC' },
                { value: 'h2', label: 'HTTP/2 (h2)' },
                { value: 'http', label: 'HTTP' },
                { value: 'xhttp', label: 'xHTTP' }
            ],
            vmess: [
                { value: 'tcp', label: 'TCP' },
                { value: 'ws', label: 'WebSocket' },
                { value: 'grpc', label: 'gRPC' },
                { value: 'h2', label: 'HTTP/2 (h2)' },
                { value: 'http', label: 'HTTP' }
            ],
            trojan: [
                { value: 'tcp', label: 'TCP' },
                { value: 'ws', label: 'WebSocket' },
                { value: 'grpc', label: 'gRPC' }
            ],
            masque: [
                { value: 'quic', label: 'QUIC' },
                { value: 'h2', label: 'HTTP/2 (h2)' }
            ]
        };
        const PROXY_TOGGLE_SUPPORT = {
            udp: new Set(['vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'socks5', 'snell']),
            tfo: new Set(['vless', 'vmess', 'trojan', 'ss', 'ssr', 'http', 'socks5', 'snell', 'ssh', 'anytls']),
            mptcp: new Set(['vless', 'vmess', 'trojan', 'ss', 'http', 'socks5', 'anytls']),
            reality: new Set(['vless', 'vmess', 'trojan']),
            smux: new Set(['vless', 'vmess', 'trojan', 'ss', 'ssr', 'http', 'socks5', 'snell', 'ssh', 'anytls', 'mieru', 'sudoku'])
        };
        const TCP_ONLY_PROXY_TOGGLES = new Set(['tfo', 'mptcp', 'smux']);
        const PROXY_TLS_MODE = {
            vless: 'toggle',
            vmess: 'toggle',
            trojan: 'required',
            http: 'toggle',
            socks5: 'toggle',
            hysteria2: 'implicit',
            hysteria: 'implicit',
            tuic: 'implicit',
            anytls: 'implicit',
            trusttunnel: 'implicit'
        };
        const PROXY_TLS_SERVER_NAME_KEY = {
            vless: 'servername',
            vmess: 'servername',
            trojan: 'servername',
            http: 'sni',
            socks5: 'sni',
            hysteria2: 'sni',
            hysteria: 'sni',
            tuic: 'sni',
            anytls: 'sni',
            trusttunnel: 'sni'
        };
        const PROXY_TLS_CLIENT_FINGERPRINT_TYPES = new Set(['vless', 'vmess', 'trojan', 'anytls', 'trusttunnel']);
        const VLESS_FLOW_OPTIONS = new Set(['xtls-rprx-vision']);
        const PACKET_ENCODING_OPTIONS = new Set(['packetaddr', 'xudp']);
        const VMESS_CIPHER_OPTIONS = new Set(['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero']);
        const HYSTERIA_PROTOCOL_OPTIONS = new Set(['udp', 'wechat-video', 'faketcp']);
        const HYSTERIA2_OBFS_OPTIONS = new Set(['salamander']);
        const BBR_PROFILE_OPTIONS = new Set(['standard', 'conservative', 'aggressive']);
        const TUIC_UDP_RELAY_MODE_OPTIONS = new Set(['native', 'quic']);
        const QUIC_CONGESTION_CONTROLLER_OPTIONS = new Set(['bbr', 'cubic', 'new_reno']);
        const MASQUE_CONGESTION_CONTROLLER_OPTIONS = new Set(['bbr']);
        const SNELL_VERSION_OPTIONS = new Set(['1', '2', '3']);
        const MIERU_TRANSPORT_OPTIONS = new Set(['TCP', 'UDP']);
        const MIERU_MULTIPLEXING_OPTIONS = new Set(['MULTIPLEXING_OFF', 'MULTIPLEXING_LOW', 'MULTIPLEXING_MIDDLE', 'MULTIPLEXING_HIGH']);
        const XHTTP_MODE_OPTIONS = new Set(['auto', 'stream-one', 'stream-up', 'packet-up']);
        const XHTTP_PADDING_PLACEMENT_OPTIONS = new Set(['queryInHeader', 'cookie', 'header', 'query']);
        const XHTTP_PADDING_METHOD_OPTIONS = new Set(['repeat-x', 'tokenish']);
        const XHTTP_UPLINK_HTTP_METHOD_OPTIONS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
        const XHTTP_UPLINK_DATA_PLACEMENT_OPTIONS = new Set(['body', 'cookie', 'header']);
        const XHTTP_KEY_PLACEMENT_OPTIONS = new Set(['path', 'query', 'cookie', 'header']);
        const XHTTP_DOWNLOAD_SETTINGS_ALLOWED_KEYS = new Set([
            'path',
            'host',
            'headers',
            'reuse-settings',
            'server',
            'port',
            'tls',
            'alpn',
            'ech-opts',
            'reality-opts',
            'skip-cert-verify',
            'fingerprint',
            'certificate',
            'private-key',
            'servername',
            'client-fingerprint'
        ]);
        const XHTTP_DOWNLOAD_SETTINGS_REUSE_ALLOWED_KEYS = new Set([
            'max-concurrency',
            'max-connections',
            'c-max-reuse-times',
            'h-max-request-times',
            'h-max-reusable-secs',
            'h-keep-alive-period'
        ]);
        const getProxyNetworkOptions = (type) => PROXY_NETWORK_OPTIONS_MAP[type] || [];
        const proxySupportsTransport = (type) => getProxyNetworkOptions(type).length > 0;
        const getProxyTlsMode = (type) => PROXY_TLS_MODE[type] || 'none';
        const proxySupportsToggle = (type, toggle) => {
            if (toggle === 'tls') return ['toggle', 'required'].includes(getProxyTlsMode(type));
            return !!PROXY_TOGGLE_SUPPORT[toggle] && PROXY_TOGGLE_SUPPORT[toggle].has(type);
        };
        const proxySupportsTlsClientFingerprint = (type) => PROXY_TLS_CLIENT_FINGERPRINT_TYPES.has(type);
        const getProxyTlsServerNameKey = (type) => PROXY_TLS_SERVER_NAME_KEY[type] || '';
        const getProxyTlsServerNameValue = (proxy) => String(proxy?.servername || proxy?.sni || '').trim();
        const proxyHasTlsSection = (proxy) => {
            const type = typeof proxy === 'string' ? proxy : proxy?.type;
            const tlsMode = getProxyTlsMode(type);
            if (tlsMode === 'implicit' || tlsMode === 'required') return true;
            if (!proxy || typeof proxy !== 'object') return tlsMode === 'toggle';
            return (tlsMode === 'toggle' && !!proxy.tls) || !!proxy.reality;
        };
        const resolveProxyNetworkState = (type, network) => {
            const options = getProxyNetworkOptions(type);
            const defaultNetwork = options[0]?.value || 'tcp';
            const requestedNetwork = String(network || '').trim();
            const allowedNetworks = new Set(options.map((item) => item.value));
            const effectiveNetwork = allowedNetworks.size === 0
                ? 'tcp'
                : (allowedNetworks.has(requestedNetwork) ? requestedNetwork : defaultNetwork);
            return {
                allowedNetworks,
                defaultNetwork,
                effectiveNetwork,
                requestedNetwork
            };
        };
        const resolveProxyCapabilities = (proxy = {}) => {
            const type = String(proxy.type || 'vless').trim() || 'vless';
            const networkState = resolveProxyNetworkState(type, proxy.network);
            const tlsMode = getProxyTlsMode(type);
            return {
                type,
                ...networkState,
                networkOptions: getProxyNetworkOptions(type),
                supportsTransport: proxySupportsTransport(type),
                tlsMode,
                hasTlsSection: proxyHasTlsSection(proxy),
                supportsTlsClientFingerprint: proxySupportsTlsClientFingerprint(type),
                toggles: {
                    udp: proxySupportsToggle(type, 'udp'),
                    tfo: proxySupportsToggle(type, 'tfo'),
                    mptcp: proxySupportsToggle(type, 'mptcp'),
                    tls: proxySupportsToggle(type, 'tls'),
                    reality: proxySupportsToggle(type, 'reality'),
                    smux: proxySupportsToggle(type, 'smux')
                }
            };
        };
        const proxyToggleRequiresTcpNetwork = (toggle) => TCP_ONLY_PROXY_TOGGLES.has(toggle);
        const proxyToggleAvailableInCurrentNetwork = (proxy = {}, toggle) => {
            const caps = resolveProxyCapabilities(proxy);
            return caps.toggles[toggle] === true
                && (!proxyToggleRequiresTcpNetwork(toggle) || !caps.supportsTransport || caps.effectiveNetwork === 'tcp');
        };
        const sanitizeProxyByCapabilities = (proxy = {}) => {
            if (!proxy || typeof proxy !== 'object') return proxy;

            const caps = resolveProxyCapabilities(proxy);

            proxy.network = caps.effectiveNetwork;

            if (!caps.toggles.udp) proxy.udp = false;
            if (!proxyToggleAvailableInCurrentNetwork(proxy, 'tfo')) proxy.tfo = false;
            if (!proxyToggleAvailableInCurrentNetwork(proxy, 'mptcp')) proxy.mptcp = false;
            if (caps.tlsMode === 'required') proxy.tls = true;
            else if (!caps.toggles.tls) proxy.tls = false;
            if (!caps.toggles.reality) proxy.reality = false;
            if (caps.type !== 'trojan' && proxy['ss-opts'] && typeof proxy['ss-opts'] === 'object') {
                proxy['ss-opts'].enabled = false;
            }
            if ((!proxy.smux?.enabled || !proxyToggleAvailableInCurrentNetwork(proxy, 'smux')) && proxy.smux && typeof proxy.smux === 'object') {
                proxy.smux.enabled = false;
            }

            return proxy;
        };
        const formatScalarListText = (value) => {
            if (Array.isArray(value)) {
                return value
                    .map((item) => String(item ?? '').trim())
                    .filter(Boolean)
                    .join('\n');
            }
            const text = String(value || '').trim();
            return text || '';
        };
        const parseScalarListText = (value) => String(value || '')
            .split(/\r?\n|,/)
            .map((item) => String(item ?? '').trim())
            .filter(Boolean);
        const hasTextValue = (value) => String(value ?? '').trim() !== '';
        const isValidPortToken = (value) => {
            const raw = String(value || '').trim();
            if (!raw) return false;
            if (/^\d+$/.test(raw)) {
                const port = Number(raw);
                return Number.isInteger(port) && port >= 1 && port <= 65535;
            }
            const match = raw.match(/^(\d+)\s*-\s*(\d+)$/);
            if (!match) return false;
            const start = Number(match[1]);
            const end = Number(match[2]);
            return Number.isInteger(start)
                && Number.isInteger(end)
                && start >= 1
                && end >= 1
                && start <= 65535
                && end <= 65535
                && start <= end;
        };
        const isValidPortRangeListText = (value) => {
            const raw = String(value || '').trim();
            if (!raw) return false;
            return raw
                .split(/[\/,]/)
                .map((item) => item.trim())
                .filter(Boolean)
                .every((item) => isValidPortToken(item));
        };
        const isValidHy2HopIntervalText = (value) => {
            const raw = String(value || '').trim();
            if (!raw) return false;
            if (/^\d+$/.test(raw)) return Number(raw) > 0;
            const match = raw.match(/^(\d+)\s*-\s*(\d+)$/);
            if (!match) return false;
            const start = Number(match[1]);
            const end = Number(match[2]);
            return Number.isInteger(start)
                && Number.isInteger(end)
                && start > 0
                && end > 0
                && start <= end;
        };
        const isValidIntegerText = (value, { min = null, allowNegative = false } = {}) => {
            const raw = String(value || '').trim();
            if (!raw) return false;
            if (!/^-?\d+$/.test(raw)) return false;
            const parsed = Number(raw);
            if (!Number.isInteger(parsed)) return false;
            if (!allowNegative && parsed < 0) return false;
            if (min !== null && parsed < min) return false;
            return true;
        };
        const isValidPositiveIntegerOrRangeText = (value, { min = 1 } = {}) => {
            const raw = String(value || '').trim();
            if (!raw) return false;
            if (/^\d+$/.test(raw)) {
                const parsed = Number(raw);
                return Number.isInteger(parsed) && parsed >= min;
            }
            const match = raw.match(/^(\d+)\s*-\s*(\d+)$/);
            if (!match) return false;
            const start = Number(match[1]);
            const end = Number(match[2]);
            return Number.isInteger(start)
                && Number.isInteger(end)
                && start >= min
                && end >= min
                && start <= end;
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
                tls: px.type === 'trojan' ? px.tls !== false : !!px.tls,
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
            if (px.type === 'tuic' && !base.uuid) base.uuid = px.uuid || '';
            return base;
        };
        const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);
        const sanitizeXhttpDownloadSettings = (value) => {
            if (!isPlainObject(value)) return undefined;
            const next = {};
            XHTTP_DOWNLOAD_SETTINGS_ALLOWED_KEYS.forEach((key) => {
                if (!(key in value)) return;
                if (key === 'reuse-settings') {
                    if (!isPlainObject(value[key])) return;
                    const reuseSettings = {};
                    XHTTP_DOWNLOAD_SETTINGS_REUSE_ALLOWED_KEYS.forEach((reuseKey) => {
                        if (value[key][reuseKey] !== undefined) reuseSettings[reuseKey] = value[key][reuseKey];
                    });
                    if (Object.keys(reuseSettings).length > 0) next[key] = reuseSettings;
                    return;
                }
                next[key] = value[key];
            });
            return Object.keys(next).length > 0 ? next : undefined;
        };
        const collectUnsupportedXhttpDownloadSettingsKeys = (value) => {
            if (!isPlainObject(value)) return [];
            const unsupported = [];
            Object.keys(value).forEach((key) => {
                if (!XHTTP_DOWNLOAD_SETTINGS_ALLOWED_KEYS.has(key)) {
                    unsupported.push(key);
                    return;
                }
                if (key === 'reuse-settings' && isPlainObject(value[key])) {
                    Object.keys(value[key]).forEach((reuseKey) => {
                        if (!XHTTP_DOWNLOAD_SETTINGS_REUSE_ALLOWED_KEYS.has(reuseKey)) unsupported.push(`reuse-settings.${reuseKey}`);
                    });
                }
            });
            return unsupported;
        };
        const deepEqual = (a, b) => {
            if (a === b) return true;
            if (Array.isArray(a) && Array.isArray(b)) {
                if (a.length !== b.length) return false;
                return a.every((item, index) => deepEqual(item, b[index]));
            }
            if (isPlainObject(a) && isPlainObject(b)) {
                const aKeys = Object.keys(a);
                const bKeys = Object.keys(b);
                if (aKeys.length !== bKeys.length) return false;
                return aKeys.every((key) => deepEqual(a[key], b[key]));
            }
            return false;
        };
        const pruneEmptyYamlValue = (value) => {
            if (value === undefined || value === null) return undefined;
            if (typeof value === 'string') return value.trim() === '' ? undefined : value;
            if (Array.isArray(value)) {
                const next = value.map((item) => pruneEmptyYamlValue(item)).filter((item) => item !== undefined);
                return next.length > 0 ? next : undefined;
            }
            if (isPlainObject(value)) {
                const next = {};
                Object.keys(value).forEach((key) => {
                    if (key.startsWith('_')) return;
                    const pruned = pruneEmptyYamlValue(value[key]);
                    if (pruned !== undefined) next[key] = pruned;
                });
                return Object.keys(next).length > 0 ? next : undefined;
            }
            return value;
        };
        const compactWithDefaults = (value, defaults, alwaysKeepKeys = new Set()) => {
            if (Array.isArray(value)) {
                if (Array.isArray(defaults) && deepEqual(value, defaults)) return undefined;
                const next = value
                    .map((item, index) => compactWithDefaults(item, Array.isArray(defaults) ? defaults[index] : undefined, alwaysKeepKeys))
                    .filter((item) => item !== undefined);
                return next.length > 0 ? next : undefined;
            }
            if (isPlainObject(value)) {
                const next = {};
                Object.keys(value).forEach((key) => {
                    if (key.startsWith('_')) return;
                    if (alwaysKeepKeys.has(key)) {
                        const kept = pruneEmptyYamlValue(value[key]);
                        if (kept !== undefined) next[key] = kept;
                        return;
                    }
                    const compacted = compactWithDefaults(value[key], defaults && defaults[key], alwaysKeepKeys);
                    if (compacted !== undefined) next[key] = compacted;
                });
                return Object.keys(next).length > 0 ? next : undefined;
            }
            if (defaults !== undefined && deepEqual(value, defaults)) return undefined;
            return pruneEmptyYamlValue(value);
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

            if (parsed.type === 'tuic') {
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

            if (parsed.type === 'wireguard' && !privateKey) {
                issues.push({
                    level: 'error',
                    message: 'WireGuard 缺少 private-key。'
                });
            }

            if (parsed.type === 'wireguard' && !publicKey) {
                issues.push({
                    level: 'error',
                    message: 'WireGuard 缺少 public-key。'
                });
            }

            if (parsed.type === 'wireguard' && !ipAddress) {
                issues.push({
                    level: 'error',
                    message: 'WireGuard 缺少本地 IP 地址。'
                });
            } else if (parsed.type === 'wireguard' && parsed['remote-dns-resolve'] && dnsEntries.length === 0) {
                issues.push({
                    level: 'warning',
                    message: 'WireGuard 开启 remote-dns-resolve 后，建议同时填写 dns。'
                });
            }

            if (parsed.type === 'masque' && !privateKey) {
                issues.push({
                    level: 'error',
                    message: 'MASQUE 缺少 private-key。'
                });
            }

            if (parsed.type === 'masque' && !publicKey) {
                issues.push({
                    level: 'error',
                    message: 'MASQUE 缺少 public-key。'
                });
            }

            if (parsed.type === 'masque' && !ipAddress) {
                issues.push({
                    level: 'error',
                    message: 'MASQUE 缺少本地 IP 地址。'
                });
            } else if (parsed.type === 'masque' && parsed['remote-dns-resolve'] && dnsEntries.length === 0) {
                issues.push({
                    level: 'warning',
                    message: 'MASQUE 开启 remote-dns-resolve 后，建议同时填写 dns。'
                });
            }

            if (parsed.type === 'masque' && congestionController && effectiveNetwork !== 'quic') {
                issues.push({
                    level: 'warning',
                    message: 'MASQUE 的 congestion-controller 仅在 QUIC 传输层下生效；当前 H2 模式会忽略它。'
                });
            } else if (parsed.type === 'masque' && congestionController && !MASQUE_CONGESTION_CONTROLLER_OPTIONS.has(congestionController)) {
                issues.push({
                    level: 'error',
                    message: `MASQUE 的 congestion-controller 官方当前仅列出 ${Array.from(MASQUE_CONGESTION_CONTROLLER_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'masque' && bbrProfile && effectiveNetwork !== 'quic') {
                issues.push({
                    level: 'warning',
                    message: 'MASQUE 的 bbr-profile 仅在 QUIC 传输层下生效。'
                });
            } else if (parsed.type === 'masque' && bbrProfile && !BBR_PROFILE_OPTIONS.has(bbrProfile)) {
                issues.push({
                    level: 'error',
                    message: `MASQUE 的 bbr-profile 仅支持 ${Array.from(BBR_PROFILE_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'ssh' && !username) {
                issues.push({
                    level: 'error',
                    message: 'SSH 缺少 username。'
                });
            }

            if (parsed.type === 'ssh' && !sshHasPassword && !sshHasPrivateKey) {
                issues.push({
                    level: 'error',
                    message: 'SSH 至少需要填写 password 或 private-key。'
                });
            } else if (parsed.type === 'ssh' && sshPrivateKeyPassphrase && !sshHasPrivateKey) {
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
            } else if (parsed.type === 'snell' && parsed.udp && snellVersion !== '3') {
                issues.push({
                    level: 'error',
                    message: 'Snell 仅在 version 3 时支持 UDP；当前版本缺失或不为 3。'
                });
            }

            if (parsed.type === 'anytls' && !password) {
                issues.push({
                    level: 'error',
                    message: 'AnyTLS 缺少 password。'
                });
            }

            if (parsed.type === 'mieru' && !username) {
                issues.push({
                    level: 'error',
                    message: 'Mieru 缺少 username。'
                });
            }

            if (parsed.type === 'mieru' && !password) {
                issues.push({
                    level: 'error',
                    message: 'Mieru 缺少 password。'
                });
            }

            if (parsed.type === 'mieru' && hasMieruPortRange && String(parsed.port || '').trim()) {
                issues.push({
                    level: 'error',
                    message: 'Mieru 的 port-range 不能与 port 同时使用。'
                });
            }

            if (parsed.type === 'mieru' && mieruTransport && !MIERU_TRANSPORT_OPTIONS.has(mieruTransport)) {
                issues.push({
                    level: 'error',
                    message: `Mieru 的 transport 仅支持 ${Array.from(MIERU_TRANSPORT_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'mieru' && mieruMultiplexing && !MIERU_MULTIPLEXING_OPTIONS.has(mieruMultiplexing)) {
                issues.push({
                    level: 'error',
                    message: `Mieru 的 multiplexing 仅支持 ${Array.from(MIERU_MULTIPLEXING_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'trusttunnel' && !username) {
                issues.push({
                    level: 'error',
                    message: 'TrustTunnel 缺少 username。'
                });
            }

            if (parsed.type === 'trusttunnel' && !password) {
                issues.push({
                    level: 'error',
                    message: 'TrustTunnel 缺少 password。'
                });
            }

            if (parsed.type === 'trusttunnel' && parsed.quic && congestionController && !QUIC_CONGESTION_CONTROLLER_OPTIONS.has(congestionController)) {
                issues.push({
                    level: 'error',
                    message: `TrustTunnel 的 congestion-controller 仅支持 ${Array.from(QUIC_CONGESTION_CONTROLLER_OPTIONS).join(' / ')}。`
                });
            }

            if (parsed.type === 'trusttunnel' && bbrProfile && !BBR_PROFILE_OPTIONS.has(bbrProfile)) {
                issues.push({
                    level: 'error',
                    message: `TrustTunnel 的 bbr-profile 仅支持 ${Array.from(BBR_PROFILE_OPTIONS).join(' / ')}。`
                });
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

            if (parsed.type === 'trusttunnel' && !parsed.quic && (trustTunnelMaxConnections > 0 || trustTunnelMinStreams > 0 || trustTunnelMaxStreams > 0)) {
                issues.push({
                    level: 'warning',
                    message: 'TrustTunnel 的 max-connections / min-streams / max-streams 仅在启用 QUIC 时生效。'
                });
            }

            if (parsed.type === 'trusttunnel' && parsed.quic && trustTunnelMaxConnections > 0 && trustTunnelMaxStreams > 0) {
                issues.push({
                    level: 'warning',
                    message: 'TrustTunnel 的 max-connections 与 max-streams 不能同时设置。'
                });
            }

            if (parsed.type === 'trusttunnel' && parsed.quic && trustTunnelMinStreams > 0 && trustTunnelMaxStreams > 0) {
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
            } else if (fingerprint && !serverName && getProxyTlsServerNameKey(parsed.type)) {
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
            const { type, tlsMode, hasTlsSection, supportsTlsClientFingerprint, defaultNetwork, effectiveNetwork } = caps;
            if (tlsMode === 'required') next.tls = true;
            else if (tlsMode !== 'toggle') delete next.tls;
            const realityEnabled = !!proxy.reality;
            const echEnabled = !!proxy['ech-opts']?.enable;
            const smuxEnabled = !!proxy.smux?.enabled;
            const brutalEnabled = !!proxy.smux?.['brutal-opts']?.enabled;
            const obfsEnabled = !!String(proxy.obfs || '').trim();
            const tlsServerNameKey = getProxyTlsServerNameKey(type);

            delete next.reality;
            if (effectiveNetwork === defaultNetwork) delete next.network;
            else next.network = effectiveNetwork;
            if (parsed.type === 'http') {
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
            if (!['vless', 'vmess'].includes(parsed.type)) delete next['packet-encoding'];
            if (parsed.type !== 'vless') delete next.encryption;
            if (parsed.type !== 'vmess') {
                delete next['global-padding'];
                delete next['authenticated-length'];
            }
            if (parsed.type !== 'trojan' || !proxy['ss-opts']?.enabled) delete next['ss-opts'];
            if (parsed.type !== 'ss' || !proxy['udp-over-tcp']) delete next['udp-over-tcp-version'];
            if (parsed.type !== 'wireguard') {
                delete next.ipv6;
                delete next['allowed-ips'];
                delete next['persistent-keepalive'];
                delete next['remote-dns-resolve'];
                delete next.dns;
                delete next['amnezia-wg-option'];
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
            if (!['wireguard', 'masque'].includes(parsed.type)) {
                delete next.ip;
                delete next.ipv6;
                delete next['remote-dns-resolve'];
                delete next.dns;
            } else if (parsed.type === 'masque' && proxy['remote-dns-resolve']) {
                next['remote-dns-resolve'] = true;
                const masqueDns = String(proxy.dns || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                if (masqueDns.length > 0) next.dns = masqueDns;
                else delete next.dns;
            } else if (parsed.type === 'masque') {
                delete next['remote-dns-resolve'];
                delete next.dns;
            }
            if (parsed.type === 'masque' && effectiveNetwork !== 'quic') {
                delete next['congestion-controller'];
                delete next['bbr-profile'];
            }
            if (parsed.type === 'tuic' && next['congestion-controller'] && next['congestion-controller'] !== 'bbr') delete next['bbr-profile'];
            if (!['tuic'].includes(parsed.type)) {
                delete next.token;
                delete next['heartbeat-interval'];
                delete next['disable-sni'];
                delete next['max-udp-relay-packet-size'];
                delete next['max-open-streams'];
            }
            if (!['hysteria', 'hysteria2'].includes(parsed.type)) {
                delete next['recv-window-conn'];
                delete next['recv-window'];
                delete next.disable_mtu_discovery;
            }
            if (!['tuic', 'hysteria'].includes(parsed.type)) delete next['fast-open'];
            if (!['hysteria2', 'tuic', 'masque', 'trusttunnel'].includes(parsed.type)) delete next['bbr-profile'];
            if (parsed.type !== 'hysteria2') {
                delete next.ports;
                delete next['hop-interval'];
            } else if (!String(proxy.ports || '').trim()) {
                delete next['hop-interval'];
            }
            if (parsed.type !== 'ssh') {
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
            if (parsed.type !== 'mieru') {
                delete next['port-range'];
                delete next['traffic-pattern'];
                delete next.transport;
                delete next.multiplexing;
            }
            if (parsed.type !== 'trusttunnel') {
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
            if (parsed.type !== 'sudoku') {
                delete next.key;
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
            if (!obfsEnabled) {
                delete next['obfs-password'];
                delete next['obfs-host'];
                delete next['obfs-param'];
            }
            if (parsed.type === 'hysteria' && next.password) {
                next['auth-str'] = next.password;
                delete next.password;
            } else if (parsed.type === 'snell' && next.password) {
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
