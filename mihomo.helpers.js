(function (window) {
    'use strict';

     

function parsePorts(str) {
    if (!str) return [];
    return str.split(',').map(s => {
        s = s.trim();
        if (s.includes('-')) return s;
        return Number(s);
    }).filter(Boolean);
}

function parsePortSpec(value) {
    const raw = String(value ?? '').trim();
    if (!raw) return null;

    const ranges = [];
    const tokens = raw
        .split(/[\/,]/)
        .map((item) => item.trim())
        .filter(Boolean);

    if (tokens.length === 0) return null;

    for (const token of tokens) {
        if (/^\d+$/.test(token)) {
            const port = Number(token);
            if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
            ranges.push({ start: port, end: port });
            continue;
        }

        const match = token.match(/^(\d+)\s*-\s*(\d+)$/);
        if (!match) return null;

        const start = Number(match[1]);
        const end = Number(match[2]);
        if (
            !Number.isInteger(start)
            || !Number.isInteger(end)
            || start < 1
            || start > 65535
            || end < 1
            || end > 65535
            || start > end
        ) {
            return null;
        }
        ranges.push({ start, end });
    }

    ranges.sort((a, b) => (a.start - b.start) || (a.end - b.end));
    const merged = [];
    ranges.forEach((range) => {
        const previous = merged[merged.length - 1];
        if (!previous || range.start > previous.end + 1) {
            merged.push({ ...range });
            return;
        }
        previous.end = Math.max(previous.end, range.end);
    });

    return merged;
}

function isValidPortSpec(value) {
    return Array.isArray(parsePortSpec(value));
}

function getPortSpecOverlap(firstValue, secondValue) {
    const firstRanges = Array.isArray(firstValue) ? firstValue : parsePortSpec(firstValue);
    const secondRanges = Array.isArray(secondValue) ? secondValue : parsePortSpec(secondValue);
    if (!Array.isArray(firstRanges) || !Array.isArray(secondRanges)) return null;

    let i = 0;
    let j = 0;
    while (i < firstRanges.length && j < secondRanges.length) {
        const first = firstRanges[i];
        const second = secondRanges[j];
        const start = Math.max(first.start, second.start);
        const end = Math.min(first.end, second.end);
        if (start <= end) return { start, end };

        if (first.end < second.end) i += 1;
        else j += 1;
    }

    return null;
}

function formatPortOverlap(range) {
    if (!range || !Number.isInteger(range.start) || !Number.isInteger(range.end)) return '';
    return range.start === range.end ? String(range.start) : `${range.start}-${range.end}`;
}

function isPortCovered(value, port) {
    const targetPort = Number(port);
    if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) return false;
    const ranges = parsePortSpec(value);
    if (!Array.isArray(ranges)) return false;
    return ranges.some((range) => targetPort >= range.start && targetPort <= range.end);
}

function getSuggestedListenerPort(config, uiState, startPort = 7895) {
    const candidates = [];
    const cfg = config && typeof config === 'object' ? config : {};
    const state = uiState && typeof uiState === 'object' ? uiState : {};

    ['mixed-port', 'port', 'socks-port', 'redir-port'].forEach((key) => {
        if (cfg[key] !== undefined && cfg[key] !== null && cfg[key] !== '') candidates.push(cfg[key]);
    });

    if (state.tproxyEnable && cfg['tproxy-port'] !== undefined && cfg['tproxy-port'] !== null && cfg['tproxy-port'] !== '') {
        candidates.push(cfg['tproxy-port']);
    }

    if (Array.isArray(cfg.listeners)) {
        cfg.listeners.forEach((listener) => {
            if (!listener) return;
            candidates.push(listener.port);
        });
    }

    for (let port = Math.max(1, Number(startPort) || 7895); port <= 65535; port += 1) {
        if (candidates.every((value) => !isPortCovered(value, port))) return port;
    }
    return 65535;
}

const TUNNEL_LISTENER_NETWORK_OPTIONS = Object.freeze(['tcp', 'udp']);

function normalizeTunnelListenerNetwork(value) {
    const source = Array.isArray(value)
        ? value
        : String(value ?? '')
            .split(/[\/,\s]+/)
            .map((item) => item.trim())
            .filter(Boolean);

    const normalized = [];
    source.forEach((item) => {
        const network = String(item || '').trim().toLowerCase();
        if (!TUNNEL_LISTENER_NETWORK_OPTIONS.includes(network) || normalized.includes(network)) return;
        normalized.push(network);
    });

    return normalized;
}

function parseHosts(str) {
    if (!str || str.trim() === '') return undefined;
    const lines = str.split('\n').map(s=>s.trim()).filter(Boolean);
    const obj = {};
    lines.forEach(l => {
        const idx = l.indexOf(':');
        if (idx > -1) {
            const k = l.substring(0, idx).trim();
            const v = l.substring(idx + 1).trim();
            obj[k] = v;
        }
    });
    return Object.keys(obj).length > 0 ? obj : undefined;
}

function parseYamlMapText(str) {
    const text = String(str || '').trim();
    if (!text) return undefined;
    if (!window.jsyaml || typeof window.jsyaml.load !== 'function') {
        throw new Error('js-yaml 未加载，无法解析 YAML 映射');
    }

    const parsed = window.jsyaml.load(text);
    if (parsed === undefined || parsed === null || parsed === '') return undefined;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('请输入 YAML 映射对象，例如 key: value');
    }

    const result = {};
    Object.keys(parsed).forEach((rawKey) => {
        const key = String(rawKey ?? '').trim();
        if (!key) return;

        const value = parsed[rawKey];
        if (Array.isArray(value)) {
            const list = value
                .map((item) => String(item ?? '').trim())
                .filter(Boolean);
            if (list.length > 0) result[key] = list;
            return;
        }

        if (value === undefined || value === null || value === '') return;
        if (typeof value === 'object') {
            throw new Error(`YAML 映射值仅支持字符串或列表: ${key}`);
        }

        result[key] = String(value).trim();
    });

    return Object.keys(result).length > 0 ? result : undefined;
}

function formatYamlMapText(map) {
    if (!map || typeof map !== 'object' || Array.isArray(map) || Object.keys(map).length === 0) return '';
    if (!window.jsyaml || typeof window.jsyaml.dump !== 'function') {
        return Object.keys(map)
            .map((key) => `${key}: ${Array.isArray(map[key]) ? map[key].join(', ') : map[key]}`)
            .join('\n');
    }

    return window.jsyaml.dump(map, {
        indent: 2,
        lineWidth: -1,
        noRefs: true,
        sortKeys: false
    }).trim();
}

function parseYamlSequenceText(str, itemTransformer) {
    const text = String(str || '').trim();
    if (!text) return undefined;
    if (!window.jsyaml || typeof window.jsyaml.load !== 'function') {
        throw new Error('js-yaml 未加载，无法解析 YAML 列表');
    }

    const parsed = window.jsyaml.load(text);
    if (parsed === undefined || parsed === null || parsed === '') return undefined;
    if (!Array.isArray(parsed)) {
        throw new Error('请输入 YAML 列表，例如 - item');
    }

    const result = parsed
        .map((item, index) => (typeof itemTransformer === 'function' ? itemTransformer(item, index) : item))
        .filter((item) => item !== undefined && item !== null && item !== '');

    return result.length > 0 ? result : undefined;
}

function formatYamlSequenceText(list) {
    if (!Array.isArray(list) || list.length === 0) return '';
    if (!window.jsyaml || typeof window.jsyaml.dump !== 'function') {
        return list.map((item) => JSON.stringify(item)).join('\n');
    }

    return window.jsyaml.dump(list, {
        indent: 2,
        lineWidth: -1,
        noRefs: true,
        sortKeys: false
    }).trim();
}

function parseYamlObjectText(str) {
    const text = String(str || '').trim();
    if (!text) return undefined;
    if (!window.jsyaml || typeof window.jsyaml.load !== 'function') {
        throw new Error('js-yaml 未加载，无法解析 YAML 对象');
    }

    const parsed = window.jsyaml.load(text);
    if (parsed === undefined || parsed === null || parsed === '') return undefined;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('请输入 YAML 对象');
    }
    return parsed;
}

function formatYamlObjectText(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj) || Object.keys(obj).length === 0) return '';
    if (!window.jsyaml || typeof window.jsyaml.dump !== 'function') {
        return JSON.stringify(obj, null, 2);
    }

    return window.jsyaml.dump(obj, {
        indent: 2,
        lineWidth: -1,
        noRefs: true,
        sortKeys: false
    }).trim();
}

function parseMarkValue(val, fallback = 111) {
    const s = String(val ?? '').trim();
    if (!s) return fallback;
    const n = parseInt(s, s.toLowerCase().startsWith('0x') ? 16 : 10);
    return Number.isInteger(n) ? n : fallback;
}

function getListenPort(val, fallback = 53) {
    const m = String(val || '').match(/(\d+)\s*$/);
    return m ? Number(m[1]) : fallback;
}

function normalizeListenAddress(val, fallback = ':53') {
    const raw = String(val ?? '').trim();
    if (!raw) return fallback;

    const match = raw.match(/(\d+)\s*$/);
    if (!match) return raw;

    const parsedPort = Number(match[1]);
    let port = Number.isInteger(parsedPort) ? parsedPort : getListenPort(fallback, 53);
    if (port < 1) port = 1;
    if (port > 65535) port = 65535;

    const prefix = raw.slice(0, match.index);
    if (!prefix && /^\d+\s*$/.test(raw)) return `:${port}`;
    return `${prefix}${port}`;
}

function replaceListenPort(val, nextPort) {
    let port = Number(nextPort);
    if (!Number.isInteger(port) || port < 1) port = 1;
    if (port > 65535) port = 65535;

    const raw = String(val ?? '').trim();
    const match = raw.match(/(\d+)\s*$/);
    if (!raw || !match) return `:${port}`;

    const prefix = raw.slice(0, match.index);
    if (!prefix && /^\d+\s*$/.test(raw)) return `:${port}`;
    return `${prefix}${port}`;
}

function parseLineList(str) {
    return String(str || '')
        .split('\n')
        .map(s => s.replace(/#.*/, '').trim())
        .filter(Boolean);
}

function parseCommaList(str) {
    return String(str || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
}

const SHADOWSOCKS_CIPHER_OPTIONS = Object.freeze([
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
    'aes-128-gcm',
    'aes-192-gcm',
    'aes-256-gcm',
    'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
    'none'
]);

const SHADOWSOCKS_2022_KEY_BYTES = Object.freeze({
    '2022-blake3-aes-128-gcm': 16,
    '2022-blake3-aes-256-gcm': 32,
    '2022-blake3-chacha20-poly1305': 32
});

function getShadowsocksCipherOptions() {
    return SHADOWSOCKS_CIPHER_OPTIONS.slice();
}

function isSupportedShadowsocksCipher(cipher) {
    return SHADOWSOCKS_CIPHER_OPTIONS.includes(String(cipher || '').trim());
}

function getShadowsocks2022KeyBytes(cipher) {
    return SHADOWSOCKS_2022_KEY_BYTES[String(cipher || '').trim()] || null;
}

function isShadowsocks2022Cipher(cipher) {
    return getShadowsocks2022KeyBytes(cipher) !== null;
}

function shadowsocksCipherRequiresPassword(cipher) {
    return String(cipher || '').trim() !== 'none';
}

function getRandomBytes(length) {
    const normalizedLength = Number(length);
    if (!Number.isInteger(normalizedLength) || normalizedLength <= 0) return null;

    const cryptoApi = (window && window.crypto) || (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
    if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') return null;

    const randomBytes = new Uint8Array(normalizedLength);
    cryptoApi.getRandomValues(randomBytes);
    return randomBytes;
}

function bytesToBase64(bytes) {
    if (!bytes || typeof bytes.length !== 'number') return '';

    let binary = '';
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });

    if (typeof btoa === 'function') return btoa(binary);
    if (typeof Buffer !== 'undefined') return Buffer.from(binary, 'binary').toString('base64');
    return '';
}

function getBase64DecodedLength(value) {
    const source = String(value || '').trim();
    if (!source) return null;
    if (!/^[A-Za-z0-9+/=]+$/.test(source)) return null;

    try {
        if (typeof atob === 'function') return atob(source).length;
        if (typeof Buffer !== 'undefined') return Buffer.from(source, 'base64').length;
    } catch (err) {
        return null;
    }

    return null;
}

function generateAsciiPassword(length = 24) {
    const randomBytes = getRandomBytes(length);
    if (!randomBytes) return '';

    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_';
    let result = '';
    randomBytes.forEach((byte) => {
        result += alphabet[byte % alphabet.length];
    });
    return result;
}

function generateShadowsocksPassword(cipher) {
    const normalizedCipher = String(cipher || '').trim();
    if (!normalizedCipher || !isSupportedShadowsocksCipher(normalizedCipher)) return '';
    if (normalizedCipher === 'none') return '';

    const keyBytes = getShadowsocks2022KeyBytes(normalizedCipher);
    if (keyBytes) {
        const randomBytes = getRandomBytes(keyBytes);
        return randomBytes ? bytesToBase64(randomBytes) : '';
    }

    return generateAsciiPassword(24);
}

function isValidShadowsocksPasswordForCipher(cipher, password) {
    const normalizedCipher = String(cipher || '').trim();
    const normalizedPassword = String(password || '').trim();

    if (!normalizedCipher) return false;
    if (normalizedCipher === 'none') return normalizedPassword === '';

    const keyBytes = getShadowsocks2022KeyBytes(normalizedCipher);
    if (!keyBytes) return normalizedPassword !== '';

    return getBase64DecodedLength(normalizedPassword) === keyBytes;
}

const DEFAULT_NFT_PRIVATE4 = `0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4`;

const DEFAULT_NFT_PRIVATE6 = `::/128
::1/128
fc00::/7
fe80::/10
2001:db8::/32
64:ff9b::/96
100::/64
ff00::/8`;

const DEFAULT_NFT_COMMON_PORTS = '22,587,465,995,993,143,80,443,853,9418';

function normalizeNftablesConfig(nft, cfg) {
    const base = (nft && typeof nft === 'object') ? nft : {};
    const ipv6 = !!base.tproxyIpv6;
    const ifaceName = (cfg && cfg['interface-name']) || '';
    const rawPort = Number(base.tproxyPort || (cfg && cfg['tproxy-port']) || 7894);

    return {
        nftTable: String(base.nftTable || 'mihomo').trim() || 'mihomo',
        tproxyPort: Number.isFinite(rawPort) && rawPort > 0 ? rawPort : 7894,
        listen: String(base.listen || (ipv6 ? '::' : '0.0.0.0')).trim() || (ipv6 ? '::' : '0.0.0.0'),
        udp: base.udp !== false,
        tproxyIpv6: ipv6,
        ingressIface: String(base.ingressIface || '').trim(),
        egressIface: String(base.egressIface || base.outInterface || ifaceName || '').trim(),
        routeMarkHex: String(base.routeMarkHex || '112').trim() || '112',
        tproxyMarkHex: String(base.tproxyMarkHex || '111').trim() || '111',
        proxyUid: String(base.proxyUid || '').trim(),
        proxyGid: String(base.proxyGid || '').trim(),
        hijackDns: ('hijackDns' in base) ? !!base.hijackDns : true,
        privateIps: String(base.privateIps || DEFAULT_NFT_PRIVATE4),
        privateIpsV6: String(base.privateIpsV6 || DEFAULT_NFT_PRIVATE6),
        bypassCnIp: !!base.bypassCnIp,
        cnIps: String(base.cnIps || ''),
        cnIpsV6: String(base.cnIpsV6 || ''),
        filterPorts: !!base.filterPorts,
        commonPorts: String((base.commonPorts && String(base.commonPorts).trim() === '22, 80, 443, 8080, 8443') ? DEFAULT_NFT_COMMON_PORTS : (base.commonPorts || DEFAULT_NFT_COMMON_PORTS))
    };
}

function getSanitizedUiStateForSave(state, cfg) {
    const cloned = JSON.parse(JSON.stringify(state || {}));
    Object.keys(cloned).forEach((key) => {
        if (/^show[A-Z]/.test(key)) {
            delete cloned[key];
        }
    });
    delete cloned.pendingAction;
    delete cloned.tproxyConflicts;
    delete cloned.localDns53Frontend;
    cloned.nftablesConfig = normalizeNftablesConfig(cloned.nftablesConfig, cfg);
    return cloned;
}

function splitByComma(str) {
    if (!str) return [];
    let result = [];
    let current = '';
    let depth = 0;
    let quote = '';
    let escaping = false;
    for (let i = 0; i < str.length; i++) {
        let char = str[i];

        if (quote) {
            current += char;
            if (escaping) {
                escaping = false;
            } else if (char === '\\') {
                escaping = true;
            } else if (char === quote) {
                quote = '';
            }
            continue;
        }

        if (char === '"' || char === "'") {
            quote = char;
            current += char;
            continue;
        }

        if (char === '(') depth++;
        if (char === ')') depth = Math.max(0, depth - 1);
        if (char === ',' && depth === 0) {
            result.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    result.push(current.trim());
    return result;
}

const deepMerge = (target, source) => {
    if (!source || typeof source !== 'object') return;
    for (const key in source) {
        if (source[key] === null || source[key] === undefined) continue;
        if (Array.isArray(source[key])) {
            target[key] = source[key];
        } else if (typeof source[key] === 'object') {
            if (!target[key] || typeof target[key] !== 'object' || Array.isArray(target[key])) {
                target[key] = {};
            }
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
};

    window.MihomoHelpers = {
        parsePorts,
        parsePortSpec,
        isValidPortSpec,
        getPortSpecOverlap,
        formatPortOverlap,
        isPortCovered,
        getSuggestedListenerPort,
        normalizeTunnelListenerNetwork,
        TUNNEL_LISTENER_NETWORK_OPTIONS,
        parseHosts,
        parseMarkValue,
        getListenPort,
        normalizeListenAddress,
        replaceListenPort,
        parseLineList,
        parseCommaList,
        getShadowsocksCipherOptions,
        isSupportedShadowsocksCipher,
        getShadowsocks2022KeyBytes,
        isShadowsocks2022Cipher,
        shadowsocksCipherRequiresPassword,
        generateShadowsocksPassword,
        isValidShadowsocksPasswordForCipher,
        DEFAULT_NFT_PRIVATE4,
        DEFAULT_NFT_PRIVATE6,
        DEFAULT_NFT_COMMON_PORTS,
        normalizeNftablesConfig,
        getSanitizedUiStateForSave,
        parseYamlMapText,
        formatYamlMapText,
        parseYamlSequenceText,
        formatYamlSequenceText,
        parseYamlObjectText,
        formatYamlObjectText,
        splitByComma,
        deepMerge
    };
})(window);
