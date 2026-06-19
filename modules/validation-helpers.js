(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const unique = (items) => Array.from(new Set(items));
    const text = (value) => String(value ?? '').trim();
    const hasText = (value) => text(value) !== '';
    const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);
    const isIntegerInRange = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;
    const splitLines = (value) => String(value || '')
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter((item) => item && !item.startsWith('#'));

    const isValidNonNegativeNumberText = (value) => {
        const raw = text(value);
        if (!raw) return false;
        const parsed = Number(raw);
        return Number.isFinite(parsed) && parsed >= 0;
    };

    const isValidPositiveNumber = (value) => {
        const parsed = Number(value);
        return Number.isFinite(parsed) && parsed > 0;
    };

    const isValidTriStateBooleanText = (value) => {
        const raw = text(value).toLowerCase();
        return raw === '' || raw === 'true' || raw === 'false';
    };

    const isValidRoutingMarkText = (value) => {
        const raw = text(value);
        if (!raw) return true;
        return /^(?:\d+|0x[0-9a-fA-F]+)$/.test(raw);
    };

    const isValidAbsoluteUrl = (value) => {
        const raw = text(value);
        if (!raw) return false;
        try {
            const parsed = new URL(raw);
            return !!parsed.protocol;
        } catch (err) {
            return false;
        }
    };

    const isValidIpv4 = (value) => {
        const raw = text(value);
        if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)) return false;
        return raw.split('.').every((item) => {
            const octet = Number(item);
            return Number.isInteger(octet) && octet >= 0 && octet <= 255;
        });
    };

    const isValidIpv6 = (value) => {
        const raw = text(value);
        if (!raw.includes(':') || !/^[0-9a-fA-F:]+$/.test(raw)) return false;
        const parts = raw.split('::');
        if (parts.length > 2) return false;
        return true;
    };

    const isValidSinglePort = (value) => {
        const raw = text(value);
        if (!/^\d+$/.test(raw)) return false;
        const port = Number(raw);
        return isIntegerInRange(port, 1, 65535);
    };

    const isValidListenAddress = (value) => {
        const raw = text(value);
        if (!raw) return false;
        const match = raw.match(/(\d+)\s*$/);
        if (!match) return false;
        return isValidSinglePort(match[1]);
    };

    const isIpLiteralWithOptionalPort = (value) => {
        const raw = text(value);
        if (!raw) return false;

        const ipv4Match = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$/);
        if (ipv4Match) {
            return isValidIpv4(ipv4Match[1]) && (!ipv4Match[2] || isValidSinglePort(ipv4Match[2]));
        }

        const bracketIpv6Match = raw.match(/^\[([0-9a-fA-F:]+)\](?::(\d+))?$/);
        if (bracketIpv6Match) {
            return isValidIpv6(bracketIpv6Match[1]) && (!bracketIpv6Match[2] || isValidSinglePort(bracketIpv6Match[2]));
        }

        return isValidIpv6(raw);
    };

    const isValidBooleanText = (value) => {
        const raw = text(value).toLowerCase();
        return raw === 'true' || raw === 'false';
    };

    const isValidPortValue = (value) => {
        const raw = text(value);
        if (!raw) return false;
        if (/^\d+$/.test(raw)) {
            const port = Number(raw);
            return Number.isInteger(port) && port > 0 && port <= 65535;
        }

        const match = raw.match(/^(\d+)\s*-\s*(\d+)$/);
        if (!match) return false;

        const start = Number(match[1]);
        const end = Number(match[2]);
        return Number.isInteger(start)
            && Number.isInteger(end)
            && start > 0
            && end > 0
            && start <= 65535
            && end <= 65535
            && start <= end;
    };

    const isValidPortListValue = (value) => {
        const raw = text(value);
        if (!raw) return false;
        return raw
            .split(/[\/,]/)
            .map((item) => item.trim())
            .filter(Boolean)
            .every((item) => isValidPortValue(item));
    };

    const collectDuplicateNames = (items, getName, createMessage, pushIssue) => {
        const counts = new Map();
        (items || []).forEach((item, index) => {
            const name = text(getName(item, index));
            if (!name) return;
            counts.set(name, (counts.get(name) || 0) + 1);
        });

        Array.from(counts.entries())
            .filter(([, count]) => count > 1)
            .forEach(([name]) => {
                pushIssue('error', createMessage(name));
            });
    };

    const describeProxy = (proxy, index) => {
        const name = text(proxy && proxy.name);
        return name ? `节点 "${name}"` : `节点 #${index + 1}`;
    };

    const describeListener = (listener, index) => {
        const name = text(listener && listener.name);
        return name ? `监听器 "${name}"` : `监听器 #${index + 1}`;
    };

    const describeProvider = (provider, index) => {
        const name = text(provider && provider.name);
        return name ? `代理提供者 "${name}"` : `代理提供者 #${index + 1}`;
    };

    const describeRuleProvider = (provider, index) => {
        const name = text(provider && provider.name);
        return name ? `规则集 "${name}"` : `规则集 #${index + 1}`;
    };

    const describeGroup = (group, index) => {
        const name = text(group && group.name);
        return name ? `策略组 "${name}"` : `策略组 #${index + 1}`;
    };

    const describeRule = (rule, index) => {
        if (rule && rule.logic) return `逻辑规则 #${index + 1}`;
        const type = text(rule && rule.type);
        return type ? `规则 #${index + 1} (${type})` : `规则 #${index + 1}`;
    };

    window.MihomoFeatureModules.ValidationHelpers = Object.freeze({
        unique,
        text,
        hasText,
        isPlainObject,
        isIntegerInRange,
        splitLines,
        isValidNonNegativeNumberText,
        isValidPositiveNumber,
        isValidTriStateBooleanText,
        isValidRoutingMarkText,
        isValidAbsoluteUrl,
        isValidIpv4,
        isValidIpv6,
        isValidSinglePort,
        isValidListenAddress,
        isIpLiteralWithOptionalPort,
        isValidBooleanText,
        isValidPortValue,
        isValidPortListValue,
        collectDuplicateNames,
        describeProxy,
        describeListener,
        describeProvider,
        describeRuleProvider,
        describeGroup,
        describeRule
    });
})(window);
