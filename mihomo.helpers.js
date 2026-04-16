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
    cloned.nftablesConfig = normalizeNftablesConfig(cloned.nftablesConfig, cfg);
    return cloned;
}

function splitByComma(str) {
    if (!str) return [];
    let result = [];
    let current = '';
    let depth = 0;
    for (let i = 0; i < str.length; i++) {
        let char = str[i];
        if (char === '(') depth++;
        if (char === ')') depth--;
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
        parseHosts,
        parseMarkValue,
        getListenPort,
        parseLineList,
        parseCommaList,
        DEFAULT_NFT_PRIVATE4,
        DEFAULT_NFT_PRIVATE6,
        DEFAULT_NFT_COMMON_PORTS,
        normalizeNftablesConfig,
        getSanitizedUiStateForSave,
        parseYamlMapText,
        formatYamlMapText,
        splitByComma,
        deepMerge
    };
})(window);
