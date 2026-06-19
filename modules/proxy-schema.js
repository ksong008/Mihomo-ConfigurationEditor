(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const PROXY_NETWORK_OPTIONS_LIBRARY = Object.freeze({
        vless: Object.freeze([
            Object.freeze({ value: 'tcp', label: 'TCP' }),
            Object.freeze({ value: 'ws', label: 'WebSocket' }),
            Object.freeze({ value: 'grpc', label: 'gRPC' }),
            Object.freeze({ value: 'h2', label: 'HTTP/2 (h2)' }),
            Object.freeze({ value: 'http', label: 'HTTP' }),
            Object.freeze({ value: 'xhttp', label: 'xHTTP' })
        ]),
        vmess: Object.freeze([
            Object.freeze({ value: 'tcp', label: 'TCP' }),
            Object.freeze({ value: 'ws', label: 'WebSocket' }),
            Object.freeze({ value: 'grpc', label: 'gRPC' }),
            Object.freeze({ value: 'h2', label: 'HTTP/2 (h2)' }),
            Object.freeze({ value: 'http', label: 'HTTP' })
        ]),
        trojan: Object.freeze([
            Object.freeze({ value: 'tcp', label: 'TCP' }),
            Object.freeze({ value: 'ws', label: 'WebSocket' }),
            Object.freeze({ value: 'grpc', label: 'gRPC' })
        ]),
        masque: Object.freeze([
            Object.freeze({ value: 'quic', label: 'QUIC' }),
            Object.freeze({ value: 'h2', label: 'HTTP/2 (h2)' })
        ])
    });
    const TCP_ONLY_PROXY_TOGGLES = new Set(['tfo', 'mptcp', 'smux']);
    const DEFAULT_PROXY_CAPABILITY_FEATURES = Object.freeze({
        topLevelHeaders: false,
        packetEncoding: false,
        encryption: false,
        vmessPadding: false,
        trojanSsOpts: false,
        udpOverTcpVersion: false,
        wireguardProfile: false,
        masqueProfile: false,
        tuicProfile: false,
        recvWindow: false,
        bbrProfile: false,
        fastOpen: false,
        hysteria2Ports: false,
        sshProfile: false,
        mieruProfile: false,
        trustTunnelProfile: false,
        sudokuProfile: false,
        openvpnProfile: false,
        passwordAlias: ''
    });
    const createProxyCapability = (value = {}) => Object.freeze({
        networkOptions: value.networkOptions || Object.freeze([]),
        toggles: Object.freeze({
            udp: false,
            tfo: false,
            mptcp: false,
            tls: false,
            reality: false,
            smux: false,
            ...(value.toggles || {})
        }),
        tlsMode: value.tlsMode || 'none',
        tlsServerNameKey: value.tlsServerNameKey || '',
        supportsTlsClientFingerprint: value.supportsTlsClientFingerprint === true,
        features: Object.freeze({
            ...DEFAULT_PROXY_CAPABILITY_FEATURES,
            ...(value.features || {})
        })
    });
    const PROXY_CAPABILITY_SCHEMA = Object.freeze({
        default: createProxyCapability(),
        vless: createProxyCapability({
            networkOptions: PROXY_NETWORK_OPTIONS_LIBRARY.vless,
            toggles: { udp: true, tfo: true, mptcp: true, tls: true, reality: true, smux: true },
            tlsMode: 'toggle',
            tlsServerNameKey: 'servername',
            supportsTlsClientFingerprint: true,
            features: { packetEncoding: true, encryption: true }
        }),
        vmess: createProxyCapability({
            networkOptions: PROXY_NETWORK_OPTIONS_LIBRARY.vmess,
            toggles: { udp: true, tfo: true, mptcp: true, tls: true, smux: true },
            tlsMode: 'toggle',
            tlsServerNameKey: 'servername',
            supportsTlsClientFingerprint: true,
            features: { packetEncoding: true, vmessPadding: true }
        }),
        trojan: createProxyCapability({
            networkOptions: PROXY_NETWORK_OPTIONS_LIBRARY.trojan,
            toggles: { udp: true, tfo: true, mptcp: true, tls: true, reality: true, smux: true },
            tlsMode: 'required',
            tlsServerNameKey: 'servername',
            supportsTlsClientFingerprint: true,
            features: { trojanSsOpts: true }
        }),
        ss: createProxyCapability({
            toggles: { udp: true, tfo: true, mptcp: true, smux: true },
            features: { udpOverTcpVersion: true }
        }),
        ssr: createProxyCapability({
            toggles: { udp: true, tfo: true, smux: true }
        }),
        hysteria2: createProxyCapability({
            toggles: { udp: true },
            tlsMode: 'implicit',
            tlsServerNameKey: 'sni',
            features: { recvWindow: true, bbrProfile: true, hysteria2Ports: true }
        }),
        hysteria: createProxyCapability({
            toggles: { udp: true },
            tlsMode: 'implicit',
            tlsServerNameKey: 'sni',
            features: { recvWindow: true, fastOpen: true, passwordAlias: 'auth-str' }
        }),
        tuic: createProxyCapability({
            toggles: { udp: true },
            tlsMode: 'implicit',
            tlsServerNameKey: 'sni',
            features: { tuicProfile: true, bbrProfile: true, fastOpen: true }
        }),
        masque: createProxyCapability({
            networkOptions: PROXY_NETWORK_OPTIONS_LIBRARY.masque,
            features: { masqueProfile: true, bbrProfile: true }
        }),
        wireguard: createProxyCapability({
            toggles: { udp: true },
            features: { wireguardProfile: true }
        }),
        http: createProxyCapability({
            toggles: { tfo: true, mptcp: true, tls: true, smux: true },
            tlsMode: 'toggle',
            tlsServerNameKey: 'sni',
            features: { topLevelHeaders: true }
        }),
        socks5: createProxyCapability({
            toggles: { udp: true, tfo: true, tls: true, smux: true },
            tlsMode: 'toggle',
            tlsServerNameKey: 'sni'
        }),
        snell: createProxyCapability({
            toggles: { udp: true, tfo: true, smux: true },
            features: { passwordAlias: 'psk' }
        }),
        ssh: createProxyCapability({
            toggles: { tfo: true },
            features: { sshProfile: true }
        }),
        anytls: createProxyCapability({
            toggles: { tfo: true, mptcp: true },
            tlsMode: 'implicit',
            tlsServerNameKey: 'sni',
            supportsTlsClientFingerprint: true
        }),
        mieru: createProxyCapability({
            toggles: { smux: true },
            features: { mieruProfile: true }
        }),
        sudoku: createProxyCapability({
            toggles: { tls: true, smux: true },
            features: { sudokuProfile: true }
        }),
        trusttunnel: createProxyCapability({
            tlsMode: 'implicit',
            tlsServerNameKey: 'sni',
            supportsTlsClientFingerprint: true,
            features: { trustTunnelProfile: true, bbrProfile: true }
        }),
        openvpn: createProxyCapability({
            toggles: { udp: true, tfo: true, mptcp: true },
            features: { openvpnProfile: true }
        })
    });

    const VLESS_FLOW_OPTIONS = new Set(['xtls-rprx-vision']);
    const PACKET_ENCODING_OPTIONS = new Set(['packetaddr', 'xudp']);
    const VMESS_CIPHER_OPTIONS = new Set(['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero']);
    const HYSTERIA_PROTOCOL_OPTIONS = new Set(['udp', 'wechat-video', 'faketcp']);
    const HYSTERIA2_OBFS_OPTIONS = new Set(['salamander', 'gecko']);
    const BBR_PROFILE_OPTIONS = new Set(['standard', 'conservative', 'aggressive']);
    const TUIC_UDP_RELAY_MODE_OPTIONS = new Set(['native', 'quic']);
    const QUIC_CONGESTION_CONTROLLER_OPTIONS = new Set(['bbr', 'cubic', 'new_reno']);
    const MASQUE_CONGESTION_CONTROLLER_OPTIONS = new Set(['bbr']);
    const OPENVPN_PROTO_OPTIONS = new Set(['udp', 'tcp']);
    const OPENVPN_DEV_OPTIONS = new Set(['tun']);
    const OPENVPN_CIPHER_OPTIONS = new Set(['AES-128-GCM', 'AES-192-GCM', 'AES-256-GCM', 'AES-128-CBC', 'AES-192-CBC', 'AES-256-CBC', 'CHACHA20-POLY1305']);
    const OPENVPN_AUTH_OPTIONS = new Set(['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512']);
    const OPENVPN_COMP_LZO_OPTIONS = new Set(['yes', 'no', 'adaptive']);
    const SNELL_VERSION_OPTIONS = new Set(['1', '2', '3', '4', '5']);
    const SNELL_UDP_VERSION_OPTIONS = new Set(['3', '4', '5']);
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

    const getProxyCapabilitySchema = (type) => PROXY_CAPABILITY_SCHEMA[String(type || '').trim()] || PROXY_CAPABILITY_SCHEMA.default;
    const getProxyNetworkOptions = (type) => getProxyCapabilitySchema(type).networkOptions;
    const proxySupportsTransport = (type) => getProxyNetworkOptions(type).length > 0;
    const getProxyTlsMode = (type) => getProxyCapabilitySchema(type).tlsMode;
    const proxySupportsToggle = (type, toggle) => getProxyCapabilitySchema(type).toggles[toggle] === true;
    const proxySupportsTlsClientFingerprint = (type) => getProxyCapabilitySchema(type).supportsTlsClientFingerprint === true;
    const getProxyTlsServerNameKey = (type) => getProxyCapabilitySchema(type).tlsServerNameKey || '';
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
        const schema = getProxyCapabilitySchema(type);
        return {
            type,
            ...networkState,
            networkOptions: schema.networkOptions,
            supportsTransport: schema.networkOptions.length > 0,
            tlsMode: schema.tlsMode,
            hasTlsSection: proxyHasTlsSection(proxy),
            supportsTlsClientFingerprint: schema.supportsTlsClientFingerprint,
            tlsServerNameKey: schema.tlsServerNameKey,
            toggles: schema.toggles,
            features: schema.features
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
        if (!caps.features.trojanSsOpts && proxy['ss-opts'] && typeof proxy['ss-opts'] === 'object') {
            proxy['ss-opts'].enabled = false;
        }
        if ((!proxy.smux?.enabled || !proxyToggleAvailableInCurrentNetwork(proxy, 'smux')) && proxy.smux && typeof proxy.smux === 'object') {
            proxy.smux.enabled = false;
        }

        return proxy;
    };

    window.MihomoFeatureModules.ProxySchema = Object.freeze({
        PROXY_CAPABILITY_SCHEMA,
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
    });
})(window);
