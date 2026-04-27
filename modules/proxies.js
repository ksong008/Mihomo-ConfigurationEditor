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
        const cloneState = (value) => {
            if (typeof globalThis.structuredClone === 'function') return globalThis.structuredClone(value);
            return JSON.parse(JSON.stringify(value));
        };
        const NETWORK_OPTION_LIBRARY = Object.freeze({
            tcp: Object.freeze({ value: 'tcp', label: 'TCP' }),
            ws: Object.freeze({ value: 'ws', label: 'WebSocket' }),
            grpc: Object.freeze({ value: 'grpc', label: 'gRPC' }),
            h2: Object.freeze({ value: 'h2', label: 'HTTP/2 (h2)' }),
            http: Object.freeze({ value: 'http', label: 'HTTP' }),
            xhttp: Object.freeze({ value: 'xhttp', label: 'xHTTP' }),
            quic: Object.freeze({ value: 'quic', label: 'QUIC' })
        });
        const createNetworkOptions = (values) => Object.freeze(
            values
                .map((value) => NETWORK_OPTION_LIBRARY[value])
                .filter(Boolean)
        );
        const createToggleSpec = (value = {}) => Object.freeze({
            udp: value.udp === true,
            tfo: value.tfo === true,
            mptcp: value.mptcp === true,
            tls: value.tls === true,
            reality: value.reality === true,
            smux: value.smux === true
        });
        const PROXY_TYPE_SPEC = Object.freeze({
            vless: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions(['tcp', 'ws', 'grpc', 'h2', 'http', 'xhttp']),
                toggles: createToggleSpec({ udp: true, tfo: true, mptcp: true, tls: true, reality: true, smux: true })
            }),
            vmess: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions(['tcp', 'ws', 'grpc', 'h2', 'http']),
                toggles: createToggleSpec({ udp: true, tfo: true, mptcp: true, tls: true, reality: false, smux: true })
            }),
            trojan: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions(['tcp', 'ws', 'grpc']),
                toggles: createToggleSpec({ udp: true, tfo: true, mptcp: true, tls: true, reality: true, smux: true })
            }),
            ss: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true, tfo: true, mptcp: true, tls: true, reality: false, smux: true })
            }),
            ssr: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true, tfo: true })
            }),
            hysteria2: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: true,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true })
            }),
            hysteria: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: true,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true })
            }),
            tuic: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: true,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true })
            }),
            masque: Object.freeze({
                defaultNetwork: 'quic',
                implicitTls: true,
                networkOptions: createNetworkOptions(['quic', 'h2']),
                toggles: createToggleSpec({})
            }),
            wireguard: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true })
            }),
            http: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ tfo: true, mptcp: true, tls: true, smux: true })
            }),
            socks5: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true, tfo: true, tls: true, smux: true })
            }),
            snell: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ udp: true, tfo: true })
            }),
            ssh: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ tfo: true })
            }),
            anytls: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: true,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ tfo: true, mptcp: true })
            }),
            mieru: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({})
            }),
            sudoku: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({ tls: true, smux: true })
            }),
            trusttunnel: Object.freeze({
                defaultNetwork: 'tcp',
                implicitTls: false,
                networkOptions: createNetworkOptions([]),
                toggles: createToggleSpec({})
            })
        });
        const getProxyTypeSpec = (type) => PROXY_TYPE_SPEC[String(type || '').trim()] || PROXY_TYPE_SPEC.vless;
        const resolveProxyCapabilities = (proxy = {}) => {
            const type = String(proxy.type || 'vless').trim() || 'vless';
            const spec = getProxyTypeSpec(type);
            const networkOptions = spec.networkOptions || [];
            const allowedNetworks = networkOptions.map((option) => option.value);
            const defaultNetwork = spec.defaultNetwork || (allowedNetworks[0] || 'tcp');
            const currentNetwork = String(proxy.network || '').trim();
            const activeNetwork = allowedNetworks.length === 0
                ? defaultNetwork
                : (allowedNetworks.includes(currentNetwork) ? currentNetwork : defaultNetwork);
            const toggles = spec.toggles || {};
            const supportsTransport = allowedNetworks.length > 0;
            const implicitTls = spec.implicitTls === true;
            const supportsTlsToggle = toggles.tls === true;
            const supportsReality = toggles.reality === true;
            const tlsSectionAvailable = implicitTls || supportsTlsToggle || supportsReality;
            const tlsSectionVisible = implicitTls || !!proxy.tls || !!proxy.reality;
            const supportsSmux = toggles.smux === true;
            const smuxAvailable = supportsSmux;
            const smuxVisible = smuxAvailable && (!supportsTransport || activeNetwork === 'tcp');

            return {
                type,
                spec,
                toggles,
                networkOptions,
                allowedNetworks,
                defaultNetwork,
                activeNetwork,
                supportsTransport,
                implicitTls,
                supportsTlsToggle,
                supportsReality,
                supportsSmux,
                smuxAvailable,
                smuxVisible,
                tlsSectionAvailable,
                tlsSectionVisible
            };
        };
        const getProxyNetworkOptions = (type) => resolveProxyCapabilities({ type }).networkOptions;
        const proxySupportsTransport = (type) => resolveProxyCapabilities({ type }).supportsTransport;
        const proxySupportsToggle = (type, toggle) => {
            const caps = resolveProxyCapabilities({ type });
            return caps.toggles[toggle] === true;
        };
        const proxyShowsTlsSection = (proxy = {}) => {
            const caps = resolveProxyCapabilities(proxy);
            return caps.tlsSectionAvailable && caps.tlsSectionVisible;
        };
        const proxyShowsSmuxSection = (proxy = {}) => {
            const caps = resolveProxyCapabilities(proxy);
            return caps.smuxVisible && !!proxy?.smux?.enabled;
        };
        const sanitizeProxyByCapabilities = (proxy = {}) => {
            if (!proxy || typeof proxy !== 'object') return proxy;

            const caps = resolveProxyCapabilities(proxy);

            proxy.network = caps.activeNetwork;

            if (!caps.toggles.udp) proxy.udp = false;
            if (!caps.toggles.tfo) proxy.tfo = false;
            if (!caps.toggles.mptcp) proxy.mptcp = false;
            if (!caps.supportsTlsToggle) proxy.tls = false;
            if (!caps.supportsReality) proxy.reality = false;
            if (proxy.type !== 'trojan' && proxy['ss-opts'] && typeof proxy['ss-opts'] === 'object') {
                proxy['ss-opts'].enabled = false;
            }
            if ((!caps.smuxAvailable || !caps.smuxVisible) && proxy.smux && typeof proxy.smux === 'object') {
                proxy.smux.enabled = false;
            }

            return proxy;
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
        const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);
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
        const sanitizeProxyNodeForYaml = (proxy) => {
            const sanitizedProxy = sanitizeProxyByCapabilities(cloneState(proxy));
            const parsed = parseSingleProxyNode(sanitizedProxy);
            if (!parsed) return null;
            const defaults = parseSingleProxyNode({ type: parsed.type });
            const next = compactWithDefaults(parsed, defaults, new Set(['name', 'type', 'server', 'port'])) || {};
            const caps = resolveProxyCapabilities(sanitizedProxy);
            const tlsToggleTypes = new Set(['vless', 'vmess', 'trojan', 'ss', 'http', 'socks5', 'sudoku']);
            const realityEnabled = !!sanitizedProxy.reality;
            const echEnabled = !!sanitizedProxy['ech-opts']?.enable;
            const smuxEnabled = proxyShowsSmuxSection(sanitizedProxy);
            const brutalEnabled = !!sanitizedProxy.smux?.['brutal-opts']?.enabled;
            const obfsEnabled = !!String(sanitizedProxy.obfs || '').trim();
            const tlsSectionEnabled = proxyShowsTlsSection(sanitizedProxy);
            const effectiveNetwork = caps.activeNetwork;
            const defaultNetwork = caps.defaultNetwork;

            delete next.reality;
            if (!caps.supportsTransport || effectiveNetwork === defaultNetwork) delete next.network;
            else next.network = effectiveNetwork;
            if (parsed.type === 'http') {
                const proxyHeaders = parseYamlMapText(sanitizedProxy._proxyHeadersText);
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
            if (next['ws-opts']) {
                const wsHeaders = parseYamlMapText(sanitizedProxy._wsHeadersText);
                if (wsHeaders) next['ws-opts'].headers = wsHeaders;
                else delete next['ws-opts'].headers;
            }
            if (next['http-opts']) {
                const httpHeaders = parseYamlMapText(sanitizedProxy._httpHeadersText);
                if (httpHeaders) next['http-opts'].headers = httpHeaders;
                else delete next['http-opts'].headers;
            }
            if (next['xhttp-opts']) {
                const xhttpHeaders = parseYamlMapText(sanitizedProxy._xhttpHeadersText);
                if (xhttpHeaders) next['xhttp-opts'].headers = xhttpHeaders;
                else delete next['xhttp-opts'].headers;
            }
            if (effectiveNetwork !== 'ws') delete next['ws-opts'];
            if (effectiveNetwork !== 'grpc') delete next['grpc-opts'];
            if (effectiveNetwork !== 'h2') delete next['h2-opts'];
            delete next['httpupgrade-opts'];
            if (effectiveNetwork !== 'http') delete next['http-opts'];
            if (effectiveNetwork !== 'xhttp') delete next['xhttp-opts'];
            if (!['vless', 'vmess'].includes(parsed.type)) delete next['packet-encoding'];
            if (parsed.type !== 'vless') delete next.encryption;
            if (parsed.type !== 'vmess') {
                delete next['global-padding'];
                delete next['authenticated-length'];
            }
            if (parsed.type !== 'trojan' || !sanitizedProxy['ss-opts']?.enabled) delete next['ss-opts'];
            if (parsed.type !== 'ss' || !sanitizedProxy['udp-over-tcp']) delete next['udp-over-tcp-version'];
            if (parsed.type !== 'wireguard') {
                delete next.ipv6;
                delete next['allowed-ips'];
                delete next['persistent-keepalive'];
                delete next['remote-dns-resolve'];
                delete next.dns;
                delete next['amnezia-wg-option'];
            } else {
                const allowedIps = String(sanitizedProxy['allowed-ips'] || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                if (allowedIps.length > 0) next['allowed-ips'] = allowedIps;
                else delete next['allowed-ips'];
                if (sanitizedProxy['remote-dns-resolve']) {
                    const wireguardDns = String(sanitizedProxy.dns || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                    if (wireguardDns.length > 0) next.dns = wireguardDns;
                    else delete next.dns;
                } else {
                    delete next.dns;
                }
                const amneziaWgOption = parseYamlObjectText(sanitizedProxy._amneziaWgOptionText);
                if (amneziaWgOption) next['amnezia-wg-option'] = amneziaWgOption;
                else delete next['amnezia-wg-option'];
                delete next['wg-dns'];
            }
            if (parsed.type !== 'masque') {
                delete next.ip;
                delete next.ipv6;
                delete next['remote-dns-resolve'];
                delete next.dns;
            } else if (sanitizedProxy['remote-dns-resolve']) {
                next['remote-dns-resolve'] = true;
                const masqueDns = String(sanitizedProxy.dns || '').split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
                if (masqueDns.length > 0) next.dns = masqueDns;
                else delete next.dns;
            } else {
                delete next['remote-dns-resolve'];
                delete next.dns;
            }
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
            if (parsed.type !== 'ssh') {
                delete next['private-key-passphrase'];
                delete next['host-key'];
                delete next['host-key-algorithms'];
            } else {
                const hostKey = String(sanitizedProxy['host-key'] || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
                const hostKeyAlgorithms = String(sanitizedProxy['host-key-algorithms'] || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
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
            } else if (!sanitizedProxy.quic) {
                delete next['max-connections'];
                delete next['min-streams'];
                delete next['max-streams'];
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
                const customTables = String(sanitizedProxy['custom-tables'] || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
                if (customTables.length > 0) next['custom-tables'] = customTables;
                else delete next['custom-tables'];
                const httpmask = parseYamlObjectText(sanitizedProxy._sudokuHttpmaskText);
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
            if (!realityEnabled) delete next['reality-opts'];
            if (!tlsSectionEnabled) {
                delete next.servername;
                delete next.certificate;
                delete next.fingerprint;
                delete next['client-fingerprint'];
                delete next.alpn;
                delete next['skip-cert-verify'];
                delete next['ech-opts'];
                if (tlsToggleTypes.has(parsed.type)) delete next['private-key'];
            }
            if (!echEnabled) delete next['ech-opts'];
            if (!smuxEnabled) delete next.smux;
            if (next.smux && !brutalEnabled) delete next.smux['brutal-opts'];
            if (next['xhttp-opts'] && !Object.keys(next['xhttp-opts']['reuse-settings'] || {}).length) delete next['xhttp-opts']['reuse-settings'];

            return pruneEmptyYamlValue(next);
        };

        return {
            PROXY_TYPE_SPEC,
            getProxyTypeSpec,
            resolveProxyCapabilities,
            sanitizeProxyByCapabilities,
            getProxyNetworkOptions,
            proxySupportsTransport,
            proxySupportsToggle,
            proxyShowsTlsSection,
            proxyShowsSmuxSection,
            parseSingleProxyNode,
            sanitizeProxyNodeForYaml
        };
    };
})(window);
