(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const validationHelpers = window.MihomoFeatureModules && window.MihomoFeatureModules.ValidationHelpers;
    if (!validationHelpers) {
        throw new Error('ValidationHelpers 未加载，请确认先引入 ./modules/validation-helpers.js');
    }

    const DNS_SCHEME_PROTOCOLS = new Set(['udp:', 'tcp:', 'tls:', 'https:', 'quic:', 'system:', 'dhcp:', 'rcode:']);
    const DNS_TLS_LIKE_PROTOCOLS = new Set(['tls:', 'https:', 'quic:']);
    const DNS_RCODE_OPTIONS = new Set([
        'success',
        'format_error',
        'server_failure',
        'name_error',
        'not_implemented',
        'refused'
    ]);
    const DNS_EXTRA_BOOLEAN_KEYS = new Set([
        'h3',
        'skip-cert-verify',
        'ecs-override',
        'disable-ipv4',
        'disable-ipv6'
    ]);
    const FAKE_IP_RULE_TYPES = new Set([
        'RULE-SET',
        'GEOSITE',
        'DOMAIN',
        'DOMAIN-SUFFIX',
        'DOMAIN-KEYWORD',
        'DOMAIN-WILDCARD',
        'DOMAIN-REGEX',
        'MATCH'
    ]);

    const createValidationDns = (options = {}) => {
        const parseYamlMapText = typeof options.parseYamlMapText === 'function'
            ? options.parseYamlMapText
            : () => ({});
        const {
            unique,
            text,
            isIntegerInRange,
            isValidIpv4,
            isValidIpv6,
            isValidSinglePort,
            isIpLiteralWithOptionalPort,
            isValidBooleanText
        } = validationHelpers;

        const splitDnsServerExtras = (value) => {
            const raw = text(value);
            if (!raw) return { base: '', extras: '' };

            const hashIndex = raw.indexOf('#');
            if (hashIndex < 0) return { base: raw, extras: '' };
            return {
                base: raw.slice(0, hashIndex).trim(),
                extras: raw.slice(hashIndex + 1).trim()
            };
        };
        const getDnsServerDescriptor = (value) => {
            const raw = text(value);
            if (!raw) return { valid: false, reason: '不能为空', needsBootstrap: false, hostname: '', base: '' };

            const { base } = splitDnsServerExtras(raw);
            if (!base) return { valid: false, reason: '基础地址不能为空', needsBootstrap: false, hostname: '', base: '' };

            if (base === 'system') {
                return { valid: true, needsBootstrap: false, hostname: '', base };
            }

            if (!base.includes('://')) {
                if (isIpLiteralWithOptionalPort(base)) {
                    return { valid: true, needsBootstrap: false, hostname: base, base };
                }
                return { valid: false, reason: '不是支持的 DNS 地址类型', needsBootstrap: false, hostname: '', base };
            }

            let parsed;
            try {
                parsed = new URL(base);
            } catch (err) {
                return { valid: false, reason: '不是有效的 DNS 地址', needsBootstrap: false, hostname: '', base };
            }

            const protocol = String(parsed.protocol || '').toLowerCase();
            if (!DNS_SCHEME_PROTOCOLS.has(protocol)) {
                return {
                    valid: false,
                    reason: `使用了不支持的 DNS 协议 "${protocol.replace(/:$/, '')}"`,
                    needsBootstrap: false,
                    hostname: '',
                    base
                };
            }

            if (protocol === 'system:') {
                if (parsed.hostname) {
                    return { valid: false, reason: 'system:// 不应携带主机名', needsBootstrap: false, hostname: '', base };
                }
                return { valid: true, needsBootstrap: false, hostname: '', base };
            }

            if (protocol === 'dhcp:') {
                if (!parsed.hostname) {
                    return { valid: false, reason: 'dhcp:// 必须指定网卡名或 system', needsBootstrap: false, hostname: '', base };
                }
                return { valid: true, needsBootstrap: false, hostname: parsed.hostname, base };
            }

            if (protocol === 'rcode:') {
                const code = text(parsed.hostname || parsed.pathname.replace(/^\/+/, ''));
                if (!DNS_RCODE_OPTIONS.has(code)) {
                    return { valid: false, reason: `rcode 值 "${code}" 不在官方支持列表中`, needsBootstrap: false, hostname: code, base };
                }
                return { valid: true, needsBootstrap: false, hostname: code, base };
            }

            if (!parsed.hostname) {
                return { valid: false, reason: '缺少主机名', needsBootstrap: false, hostname: '', base };
            }

            if (protocol === 'https:' && (!parsed.pathname || parsed.pathname === '/')) {
                return { valid: false, reason: 'DoH 地址缺少路径', needsBootstrap: false, hostname: parsed.hostname, base };
            }

            const hostname = parsed.hostname;
            return {
                valid: true,
                needsBootstrap: !isValidIpv4(hostname) && !isValidIpv6(hostname),
                hostname,
                base
            };
        };
        const isValidDnsEcsValue = (value) => {
            const raw = text(value);
            if (!raw) return false;

            const match = raw.match(/^(.+)\/(\d{1,3})$/);
            if (!match) {
                return isValidIpv4(raw) || isValidIpv6(raw);
            }

            const host = text(match[1]);
            const prefix = Number(match[2]);
            if (isValidIpv4(host)) return isIntegerInRange(prefix, 0, 32);
            if (isValidIpv6(host)) return isIntegerInRange(prefix, 0, 128);
            return false;
        };
        const validateDnsServerExtras = (rawValue, label, pushIssue, context = {}) => {
            const { validDnsRouteTargets = new Set(), knownInterfaceNames = new Set() } = context;
            const { base, extras } = splitDnsServerExtras(rawValue);
            if (!extras) return { usesRules: false };

            let protocol = '';
            if (base && base.includes('://')) {
                try {
                    protocol = String(new URL(base).protocol || '').toLowerCase();
                } catch (err) {
                    protocol = '';
                }
            }

            const segments = extras
                .split('&')
                .map((item) => item.trim())
                .filter(Boolean);
            let routeTarget = '';
            let usesRules = false;

            segments.forEach((segment) => {
                const eqIndex = segment.indexOf('=');
                if (eqIndex < 0) {
                    const lower = segment.toLowerCase();
                    if (lower === 'ecs') {
                        pushIssue('error', `${label} 的 DNS 附加参数 ecs 缺少值。`);
                        return;
                    }
                    if (DNS_EXTRA_BOOLEAN_KEYS.has(lower)) {
                        if (lower === 'h3' && protocol && protocol !== 'https:') {
                            pushIssue('warning', `${label} 的 h3 仅对 https:// 类型的 DoH 地址生效。`);
                        }
                        if (lower === 'skip-cert-verify' && protocol && !DNS_TLS_LIKE_PROTOCOLS.has(protocol)) {
                            pushIssue('warning', `${label} 的 skip-cert-verify 仅对 TLS/HTTPS/QUIC 类型的 DNS 地址生效。`);
                        }
                        return;
                    }

                    const disableQtypeMatch = lower.match(/^disable-qtype-(\d+)$/);
                    if (disableQtypeMatch) {
                        const qtype = Number(disableQtypeMatch[1]);
                        if (!isIntegerInRange(qtype, 1, 65535)) {
                            pushIssue('error', `${label} 的 disable-qtype 参数 "${segment}" 不在有效范围内。`);
                        }
                        return;
                    }

                    if (routeTarget) {
                        pushIssue('error', `${label} 同时指定了多个 # 连接目标："${routeTarget}" 和 "${segment}"。`);
                        return;
                    }

                    routeTarget = segment;
                    if (lower === 'rules') {
                        usesRules = true;
                        return;
                    }

                    if (!validDnsRouteTargets.has(segment) && !knownInterfaceNames.has(segment)) {
                        pushIssue('warning', `${label} 的 DNS 连接目标 "${segment}" 不是当前配置中的代理/策略组；如果它也不是系统网卡名，请检查拼写。`);
                    }
                    return;
                }

                const keyRaw = segment.slice(0, eqIndex).trim();
                const valueRaw = segment.slice(eqIndex + 1).trim();
                const key = keyRaw.toLowerCase();
                if (!key) {
                    pushIssue('error', `${label} 存在空的 DNS 附加参数名。`);
                    return;
                }

                if (key === 'ecs') {
                    if (!isValidDnsEcsValue(valueRaw)) {
                        pushIssue('error', `${label} 的 ecs 值 "${valueRaw || '(空)'}" 不是有效的 IP 或 IP/prefix。`);
                    }
                    return;
                }

                if (DNS_EXTRA_BOOLEAN_KEYS.has(key)) {
                    if (!isValidBooleanText(valueRaw)) {
                        pushIssue('error', `${label} 的 ${keyRaw} 必须是 true 或 false。`);
                    }
                    if (key === 'h3' && protocol && protocol !== 'https:') {
                        pushIssue('warning', `${label} 的 h3 仅对 https:// 类型的 DoH 地址生效。`);
                    }
                    if (key === 'skip-cert-verify' && protocol && !DNS_TLS_LIKE_PROTOCOLS.has(protocol)) {
                        pushIssue('warning', `${label} 的 skip-cert-verify 仅对 TLS/HTTPS/QUIC 类型的 DNS 地址生效。`);
                    }
                    return;
                }

                const disableQtypeMatch = key.match(/^disable-qtype-(\d+)$/);
                if (disableQtypeMatch) {
                    const qtype = Number(disableQtypeMatch[1]);
                    if (!isIntegerInRange(qtype, 1, 65535)) {
                        pushIssue('error', `${label} 的 disable-qtype 参数 "${keyRaw}" 不在有效范围内。`);
                    }
                    if (!isValidBooleanText(valueRaw)) {
                        pushIssue('error', `${label} 的 ${keyRaw} 必须是 true 或 false。`);
                    }
                    return;
                }

                pushIssue('error', `${label} 使用了不支持的 DNS 附加参数 "${keyRaw}"。`);
            });

            return { usesRules };
        };
        const validateDnsServerList = (items, label, pushIssue, options = {}) => {
            const { allowBootstrapHostname = true, validDnsRouteTargets, knownInterfaceNames } = options;
            const needsBootstrapEntries = [];
            let usesRules = false;

            (items || []).forEach((item, index) => {
                const raw = text(item);
                if (!raw) return;

                const descriptor = getDnsServerDescriptor(raw);
                if (!descriptor.valid) {
                    pushIssue('error', `${label} 第 ${index + 1} 项无效：${descriptor.reason}。`);
                    return;
                }
                if (!allowBootstrapHostname && descriptor.needsBootstrap) {
                    pushIssue('error', `${label} 第 ${index + 1} 项不能依赖域名引导解析：${raw}`);
                    return;
                }
                if (allowBootstrapHostname && descriptor.needsBootstrap) {
                    needsBootstrapEntries.push(raw);
                }
                const extrasResult = validateDnsServerExtras(raw, `${label} 第 ${index + 1} 项`, pushIssue, {
                    validDnsRouteTargets,
                    knownInterfaceNames
                });
                if (extrasResult.usesRules) usesRules = true;
            });

            return {
                entries: needsBootstrapEntries,
                usesRules
            };
        };
        const validateExpectedStatus = (value) => {
            const raw = text(value);
            if (!raw || raw === '*') return true;

            return raw.split('/').every((token) => {
                const part = text(token);
                if (!part) return false;

                if (/^\d{3}$/.test(part)) {
                    return isIntegerInRange(Number(part), 100, 599);
                }

                const rangeMatch = part.match(/^(\d{3})-(\d{3})$/);
                if (!rangeMatch) return false;

                const start = Number(rangeMatch[1]);
                const end = Number(rangeMatch[2]);
                return isIntegerInRange(start, 100, 599)
                    && isIntegerInRange(end, 100, 599)
                    && start <= end;
            });
        };
        const validateDnsPolicyMap = (rawText, label, ruleProviderNameSet, pushIssue, options = {}) => {
            const source = text(rawText);
            if (!source) return { entries: [], hasBootstrapDependency: false, usesRules: false };

            let parsed;
            try {
                parsed = parseYamlMapText(source);
            } catch (err) {
                pushIssue('error', `${label} YAML 无法解析：${err.message}`);
                return { entries: [], hasBootstrapDependency: false, usesRules: false };
            }

            const bootstrapEntries = [];
            let usesRules = false;
            Object.keys(parsed || {}).forEach((rawKey) => {
                const key = text(rawKey);
                if (!key) return;

                const ruleSetMatch = key.match(/^rule-set:(.+)$/i);
                if (ruleSetMatch) {
                    const ref = text(ruleSetMatch[1]);
                    if (!ref) {
                        pushIssue('error', `${label} 中存在空的 rule-set 引用。`);
                    } else if (!ruleProviderNameSet.has(ref)) {
                        pushIssue('error', `${label} 引用了不存在的 rule-provider "${ref}"。`);
                    }
                }

                const values = Array.isArray(parsed[rawKey]) ? parsed[rawKey] : [parsed[rawKey]];
                const result = validateDnsServerList(values, `${label} 键 "${key}" 的 DNS`, pushIssue, {
                    allowBootstrapHostname: true,
                    validDnsRouteTargets: options.validDnsRouteTargets,
                    knownInterfaceNames: options.knownInterfaceNames
                });
                bootstrapEntries.push(...result.entries);
                if (result.usesRules) usesRules = true;
            });

            return {
                entries: unique(bootstrapEntries),
                hasBootstrapDependency: bootstrapEntries.length > 0,
                usesRules
            };
        };
        const validateFakeIpRuleLines = (items, label, ruleProviderNameSet, pushIssue) => {
            (items || []).forEach((line, index) => {
                const parts = String(line || '').split(',').map((item) => item.trim()).filter(Boolean);
                if (parts.length < 2) {
                    pushIssue('error', `${label} 第 ${index + 1} 行格式无效。`);
                    return;
                }

                const type = text(parts[0]).toUpperCase();
                const target = text(parts[parts.length - 1]).toLowerCase();
                if (!FAKE_IP_RULE_TYPES.has(type)) {
                    pushIssue('error', `${label} 第 ${index + 1} 行使用了不支持的规则类型 "${parts[0]}"。`);
                }
                if (!['fake-ip', 'real-ip'].includes(target)) {
                    pushIssue('error', `${label} 第 ${index + 1} 行的目标必须是 fake-ip 或 real-ip。`);
                }
                if (type === 'RULE-SET') {
                    const ref = text(parts[1]);
                    if (!ref) {
                        pushIssue('error', `${label} 第 ${index + 1} 行缺少 RULE-SET 名称。`);
                    } else if (!ruleProviderNameSet.has(ref)) {
                        pushIssue('error', `${label} 第 ${index + 1} 行引用了不存在的 rule-provider "${ref}"。`);
                    }
                }
                if (type === 'MATCH' && parts.length !== 2) {
                    pushIssue('warning', `${label} 第 ${index + 1} 行是 MATCH 规则，通常只需要写目标。`);
                }
            });
        };

        return {
            splitDnsServerExtras,
            getDnsServerDescriptor,
            isValidDnsEcsValue,
            validateDnsServerExtras,
            validateExpectedStatus,
            validateDnsServerList,
            validateDnsPolicyMap,
            validateFakeIpRuleLines
        };
    };

    window.MihomoFeatureModules.ValidationDns = Object.freeze({
        createValidationDns
    });
})(window);
