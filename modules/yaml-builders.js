(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const {
        parseYamlSequenceText,
        parseYamlObjectText,
        normalizeTunnelListenerNetwork
    } = window.MihomoHelpers;
    const DEFAULT_FAKE_IP_RANGE6 = 'fc00::/18';
    const SUPPORTED_LISTENER_TYPES = new Set(['mixed', 'http', 'socks', 'redir', 'tproxy', 'shadowsocks', 'tunnel']);

    const getRuleProviderPathExt = (format) => format === 'text' ? 'list' : (format || 'mrs');
    const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);

    const parseListenerUsersText = (text) => {
        const rawText = String(text || '').trim();
        if (!rawText) return undefined;

        let sequenceError = null;
        try {
            const parsedList = parseYamlSequenceText(rawText, (item) => item);
            if (parsedList && parsedList.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
                return parsedList;
            }
        } catch (err) {
            sequenceError = err;
        }

        const parsedObject = parseYamlObjectText(rawText);
        if (parsedObject && typeof parsedObject === 'object' && !Array.isArray(parsedObject)) {
            return [parsedObject];
        }

        const detail = sequenceError && sequenceError.message ? `；列表解析错误：${sequenceError.message}` : '';
        throw new Error(`users 请输入 YAML 列表、JSON 数组，或单个 JSON/YAML 对象${detail}`);
    };

    const pruneEmptyYamlValue = (value) => {
        if (value === undefined || value === null) return undefined;
        if (typeof value === 'string') return value.trim() === '' ? undefined : value;
        if (Array.isArray(value)) {
            const next = value
                .map((item) => pruneEmptyYamlValue(item))
                .filter((item) => item !== undefined);
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

    const stripDefaultFalseFlags = (value, defaults) => {
        if (value === undefined || value === null) return value;
        if (value === false && defaults === false) return undefined;

        if (Array.isArray(value)) {
            const next = value
                .map((item, index) => stripDefaultFalseFlags(item, Array.isArray(defaults) ? defaults[index] : undefined))
                .filter((item) => item !== undefined);
            return next.length > 0 ? next : undefined;
        }

        if (isPlainObject(value)) {
            const next = {};
            Object.keys(value).forEach((key) => {
                if (key.startsWith('_')) return;
                const stripped = stripDefaultFalseFlags(value[key], defaults && defaults[key]);
                if (stripped !== undefined) next[key] = stripped;
            });
            return Object.keys(next).length > 0 ? next : undefined;
        }

        return value;
    };

    const sanitizeListenerForYaml = (listener) => {
        const type = String(listener.type || '').trim();
        if (!SUPPORTED_LISTENER_TYPES.has(type)) {
            const preserved = { ...listener, type };
            delete preserved._usersText;
            delete preserved._shadowTlsText;
            delete preserved._kcpTunText;
            return pruneEmptyYamlValue(preserved);
        }
        const nextListener = {
            name: String(listener.name || '').trim(),
            type,
            listen: String(listener.listen || '').trim(),
            port: listener.port
        };
        if (['mixed', 'socks', 'tproxy', 'shadowsocks'].includes(type) && listener.udp !== undefined) nextListener.udp = listener.udp;
        if (listener.proxy) nextListener.proxy = String(listener.proxy).trim();
        if (listener.rule) nextListener.rule = String(listener.rule).trim();
        if (listener.token) nextListener.token = String(listener.token).trim();

        if (['mixed', 'http', 'socks'].includes(type)) {
            if (typeof listener._usersText === 'string' && listener._usersText.trim()) {
                nextListener.users = parseListenerUsersText(listener._usersText);
            } else if (Array.isArray(listener.users) && listener.users.length > 0) {
                nextListener.users = listener.users;
            }
            if (listener.certificate) nextListener.certificate = String(listener.certificate).trim();
            if (listener['private-key']) nextListener['private-key'] = String(listener['private-key']).trim();
            if (listener['client-auth-type']) nextListener['client-auth-type'] = String(listener['client-auth-type']).trim();
            if (listener['client-auth-cert']) nextListener['client-auth-cert'] = String(listener['client-auth-cert']).trim();
            if (listener['ech-key']) nextListener['ech-key'] = String(listener['ech-key']).trim();
            if (listener['ech-cert']) nextListener['ech-cert'] = String(listener['ech-cert']).trim();
        }

        if (type === 'shadowsocks') {
            if (listener.cipher) nextListener.cipher = String(listener.cipher).trim();
            if (listener.password) nextListener.password = String(listener.password).trim();
            if (typeof listener._shadowTlsText === 'string' && listener._shadowTlsText.trim()) {
                nextListener['shadow-tls'] = parseYamlObjectText(listener._shadowTlsText);
            } else if (isPlainObject(listener['shadow-tls'])) {
                nextListener['shadow-tls'] = listener['shadow-tls'];
            }
            if (typeof listener._kcpTunText === 'string' && listener._kcpTunText.trim()) {
                nextListener['kcp-tun'] = parseYamlObjectText(listener._kcpTunText);
            } else if (isPlainObject(listener['kcp-tun'])) {
                nextListener['kcp-tun'] = listener['kcp-tun'];
            }
        }
        if (type === 'tunnel') {
            const network = normalizeTunnelListenerNetwork(listener.network);
            if (network.length > 0) nextListener.network = network;
            if (listener.target) nextListener.target = String(listener.target).trim();
        }
        return pruneEmptyYamlValue(nextListener);
    };

    window.MihomoFeatureModules.YamlBuilders = Object.freeze({
        DEFAULT_FAKE_IP_RANGE6,
        getRuleProviderPathExt,
        isPlainObject,
        parseListenerUsersText,
        pruneEmptyYamlValue,
        stripDefaultFalseFlags,
        sanitizeListenerForYaml
    });
})(window);
