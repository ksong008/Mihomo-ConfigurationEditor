(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const proxySchema = window.MihomoFeatureModules && window.MihomoFeatureModules.ProxySchema;
    if (!proxySchema) {
        throw new Error('ProxySchema 未加载，请确认先引入 ./modules/proxy-schema.js');
    }

    const {
        XHTTP_DOWNLOAD_SETTINGS_ALLOWED_KEYS,
        XHTTP_DOWNLOAD_SETTINGS_REUSE_ALLOWED_KEYS
    } = proxySchema;

    const normalizeOpenvpnProtoValue = (value) => {
        const raw = String(value || '').trim().toLowerCase();
        if (!raw) return 'udp';
        if (raw === 'udp4') return 'udp';
        if (raw === 'tcp-client' || raw === 'tcp4' || raw === 'tcp4-client') return 'tcp';
        return raw;
    };

    const normalizeOpenvpnCipherValue = (value) => {
        const raw = String(value || '').trim().toUpperCase();
        if (!raw) return 'AES-128-GCM';
        if (raw === 'AES-CBC') return 'AES-128-CBC';
        return raw;
    };

    const normalizeOpenvpnAuthValue = (value) => {
        const raw = String(value || '').trim().toUpperCase();
        if (!raw) return 'SHA256';
        if (raw === 'SHA-1') return 'SHA1';
        return raw;
    };

    const normalizeOpenvpnCompLzoValue = (value) => String(value || '').trim().toLowerCase();

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

    window.MihomoFeatureModules.ProxyNodeUtils = Object.freeze({
        normalizeOpenvpnProtoValue,
        normalizeOpenvpnCipherValue,
        normalizeOpenvpnAuthValue,
        normalizeOpenvpnCompLzoValue,
        formatScalarListText,
        parseScalarListText,
        hasTextValue,
        isValidPortToken,
        isValidPortRangeListText,
        isValidHy2HopIntervalText,
        isValidIntegerText,
        isValidPositiveIntegerOrRangeText,
        isPlainObject,
        sanitizeXhttpDownloadSettings,
        collectUnsupportedXhttpDownloadSettingsKeys,
        deepEqual,
        pruneEmptyYamlValue,
        compactWithDefaults
    });
})(window);
