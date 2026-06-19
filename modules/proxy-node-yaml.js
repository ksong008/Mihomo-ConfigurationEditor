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

    const createProxyNodeYaml = (options = {}) => {
        const parseSingleProxyNode = options.parseSingleProxyNode;
        if (typeof parseSingleProxyNode !== 'function') {
            throw new Error('parseSingleProxyNode 未提供，无法创建代理节点 YAML 清洗器');
        }
        const parseYamlMapText = typeof options.parseYamlMapText === 'function'
            ? options.parseYamlMapText
            : () => undefined;
        const parseYamlObjectText = typeof options.parseYamlObjectText === 'function'
            ? options.parseYamlObjectText
            : () => undefined;

        const {
            getProxyTlsServerNameValue,
            resolveProxyCapabilities,
            proxyToggleAvailableInCurrentNetwork
        } = proxySchema;
        const {
            parseScalarListText,
            sanitizeXhttpDownloadSettings,
            pruneEmptyYamlValue,
            compactWithDefaults
        } = proxyNodeUtils;

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
            sanitizeProxyNodeForYaml
        };
    };

    window.MihomoFeatureModules.ProxyNodeYaml = Object.freeze({
        createProxyNodeYaml
    });
})(window);
