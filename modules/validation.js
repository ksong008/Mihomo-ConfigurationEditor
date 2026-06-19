(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createValidationModule = function (ctx) {
        const {
            computed,
            config,
            uiState,
            providersList,
            ruleProvidersList,
            getProxyValidationIssues,
            getRuleProviderUrl
        } = ctx;
        const {
            parseYamlMapText,
            parseYamlSequenceText,
            parseYamlObjectText,
            getShadowsocksCipherOptions,
            getShadowsocks2022KeyBytes,
            shadowsocksCipherRequiresPassword,
            isValidShadowsocksPasswordForCipher,
            parsePortSpec,
            getPortSpecOverlap,
            formatPortOverlap,
            normalizeTunnelListenerNetwork
        } = window.MihomoHelpers;
        const validationHelpers = window.MihomoFeatureModules && window.MihomoFeatureModules.ValidationHelpers;
        if (!validationHelpers) {
            throw new Error('ValidationHelpers 未加载，请确认先引入 ./modules/validation-helpers.js');
        }
        const {
            unique,
            text,
            hasText,
            isPlainObject,
            splitLines,
            isValidNonNegativeNumberText,
            isValidPositiveNumber,
            isValidTriStateBooleanText,
            isValidRoutingMarkText,
            isValidAbsoluteUrl,
            isValidListenAddress,
            isValidPortValue,
            isValidPortListValue,
            collectDuplicateNames,
            describeProxy,
            describeListener,
            describeProvider,
            describeRuleProvider,
            describeGroup,
            describeRule
        } = validationHelpers;
        const validationDns = window.MihomoFeatureModules && window.MihomoFeatureModules.ValidationDns;
        if (!validationDns) {
            throw new Error('ValidationDns 未加载，请确认先引入 ./modules/validation-dns.js');
        }

        const BUILTIN_RULE_TARGETS = ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'COMPATIBLE'];
        const URL_TEST_GROUP_TYPES = new Set(['url-test', 'fallback', 'load-balance']);
        const SUPPORTED_PROXY_GROUP_TYPES = new Set(['select', 'url-test', 'fallback', 'load-balance']);
        const SUPPORTED_PROXY_PROVIDER_TYPES = new Set(['http', 'file', 'inline']);
        const SUPPORTED_RULE_PROVIDER_TYPES = new Set(['http', 'file', 'inline']);
        const SUPPORTED_RULE_PROVIDER_BEHAVIORS = new Set(['domain', 'ipcidr', 'classical']);
        const SUPPORTED_RULE_PROVIDER_FORMATS = new Set(['mrs', 'yaml', 'text']);
        const IP_VERSION_OPTIONS = new Set(['ipv4', 'ipv6', 'dual', 'ipv4-prefer', 'ipv6-prefer']);
        const LOAD_BALANCE_STRATEGY_OPTIONS = new Set(['consistent-hashing', 'round-robin', 'sticky-sessions']);
        const SUPPORTED_SIMPLE_LISTENER_TYPES = new Set(['mixed', 'http', 'socks', 'redir', 'tproxy', 'shadowsocks', 'tunnel']);
        const SUPPORTED_LISTENER_CLIENT_AUTH_TYPES = new Set([
            'request',
            'skip',
            'require-any',
            'verify-if-given',
            'require-and-verify'
        ]);
        const SUPPORTED_LISTENER_SHADOWSOCKS_CIPHERS = new Set(getShadowsocksCipherOptions());
        const SUPPORTED_TUNNEL_LISTENER_NETWORKS = new Set(['tcp', 'udp']);
        const RELAY_UDP_HEAD_TAIL_TYPES = new Set(['vmess', 'vless', 'trojan', 'ss', 'ssr', 'tuic']);
        const {
            validateDnsServerList,
            validateDnsPolicyMap,
            validateFakeIpRuleLines
        } = validationDns.createValidationDns({
            parseYamlMapText
        });
        const parseListenerUsersText = (rawText) => {
            const source = text(rawText);
            if (!source) return [];

            let sequenceError = null;
            try {
                const parsedList = parseYamlSequenceText(source, (item) => item);
                if (parsedList && parsedList.every((item) => isPlainObject(item))) {
                    return parsedList;
                }
            } catch (err) {
                sequenceError = err;
            }

            const parsedObject = parseYamlObjectText(source);
            if (isPlainObject(parsedObject)) {
                return [parsedObject];
            }

            const detail = sequenceError && sequenceError.message ? `；列表解析错误：${sequenceError.message}` : '';
            throw new Error(`users 请输入 YAML 列表、JSON 数组，或单个 JSON/YAML 对象${detail}`);
        };
        const validateListenerUsers = (users, label, pushIssue) => {
            users.forEach((user, index) => {
                if (!isPlainObject(user)) {
                    pushIssue('error', `${label} 的 users 第 ${index + 1} 项必须是对象。`);
                    return;
                }

                const username = text(user.username);
                const password = text(user.password);
                if (!username && !password) {
                    return;
                }
                if (!username) {
                    pushIssue('error', `${label} 的 users 第 ${index + 1} 项缺少 username。`);
                }
                if (!password) {
                    pushIssue('error', `${label} 的 users 第 ${index + 1} 项缺少 password。`);
                }
            });
        };
        const validateProxyNameOverride = (rawText, label, pushIssue) => {
            const source = text(rawText);
            if (!source) return;

            try {
                parseYamlSequenceText(source, (item, index) => {
                    if (!isPlainObject(item)) {
                        throw new Error(`第 ${index + 1} 项必须是映射对象`);
                    }

                    const pattern = text(item.pattern);
                    const target = text(item.target);
                    if (!pattern || !target) {
                        throw new Error(`第 ${index + 1} 项必须同时包含 pattern 和 target`);
                    }

                    return { pattern, target };
                });
            } catch (err) {
                pushIssue('error', `${label} 的 override.proxy-name 格式无效：${err.message}`);
            }
        };
        const validateYamlHeaders = (rawText, label, pushIssue) => {
            const source = text(rawText);
            if (!source) return;

            try {
                parseYamlMapText(source);
            } catch (err) {
                pushIssue('error', `${label} 的 header YAML 无法解析：${err.message}`);
            }
        };

        const runtimeValidationIssues = computed(() => {
            const issues = [];
            const seen = new Set();
            const pushIssue = (level, message) => {
                const normalizedLevel = level === 'warning' ? 'warning' : 'error';
                const normalizedMessage = text(message);
                if (!normalizedMessage) return;

                const key = `${normalizedLevel}:${normalizedMessage}`;
                if (seen.has(key)) return;
                seen.add(key);
                issues.push({ level: normalizedLevel, message: normalizedMessage });
            };

            const proxies = Array.isArray(config.value && config.value.proxies) ? config.value.proxies : [];
            const listeners = Array.isArray(config.value && config.value.listeners) ? config.value.listeners : [];
            const proxyGroups = Array.isArray(config.value && config.value['proxy-groups']) ? config.value['proxy-groups'] : [];
            const providers = Array.isArray(providersList.value) ? providersList.value : [];
            const ruleProviders = Array.isArray(ruleProvidersList.value) ? ruleProvidersList.value : [];
            const rules = Array.isArray(uiState.value && uiState.value.rules) ? uiState.value.rules : [];
            const dns = config.value && config.value.dns ? config.value.dns : null;

            const proxyNames = proxies.map((proxy) => text(proxy && proxy.name)).filter(Boolean);
            const groupNames = proxyGroups.map((group) => text(group && group.name)).filter(Boolean);
            const providerNames = providers.map((provider) => text(provider && provider.name)).filter(Boolean);
            const ruleProviderNames = ruleProviders.map((provider) => text(provider && provider.name)).filter(Boolean);
            const validRuleTargets = new Set([...BUILTIN_RULE_TARGETS, ...proxyNames, ...groupNames]);
            const validDialerTargets = new Set(validRuleTargets);
            const providerNameSet = new Set(providerNames);
            const ruleProviderNameSet = new Set(ruleProviderNames);
            const proxyNameSet = new Set(proxyNames);
            const groupNameSet = new Set(groupNames);
            const validDnsRouteTargets = new Set([...proxyNameSet, ...groupNameSet]);
            const knownInterfaceNames = new Set([
                text(config.value && config.value['interface-name']),
                ...proxies.map((proxy) => text(proxy && proxy['interface-name'])),
                ...proxyGroups.map((group) => text(group && group['interface-name']))
            ].filter(Boolean));
            const proxyByName = new Map();
            proxies.forEach((proxy) => {
                const name = text(proxy && proxy.name);
                if (!name || proxyByName.has(name)) return;
                proxyByName.set(name, proxy);
            });

            let subRuleNames = new Set();
            let subRuleParseOk = true;
            const subRulesText = text(uiState.value && uiState.value.subRulesYaml);
            if (subRulesText) {
                try {
                    const parsed = parseYamlObjectText(subRulesText);
                    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                        pushIssue('error', 'sub-rules 必须是键值映射对象。');
                        subRuleParseOk = false;
                    } else {
                        subRuleNames = new Set(
                            Object.keys(parsed)
                                .map((name) => text(name))
                                .filter(Boolean)
                        );
                    }
                } catch (err) {
                    pushIssue('error', `sub-rules YAML 解析失败：${err.message}`);
                    subRuleParseOk = false;
                }
            }

            collectDuplicateNames(listeners, (item) => item && item.name, (name) => `监听器名称重复：${name}`, pushIssue);
            collectDuplicateNames(proxies, (item) => item && item.name, (name) => `节点名称重复：${name}`, pushIssue);
            collectDuplicateNames(providers, (item) => item && item.name, (name) => `代理提供者名称重复：${name}`, pushIssue);
            collectDuplicateNames(ruleProviders, (item) => item && item.name, (name) => `规则集名称重复：${name}`, pushIssue);
            collectDuplicateNames(proxyGroups, (item) => item && item.name, (name) => `策略组名称重复：${name}`, pushIssue);

            proxyNames.forEach((name) => {
                if (groupNameSet.has(name)) {
                    pushIssue('error', `节点与策略组名称冲突：${name}`);
                }
            });

            proxies.forEach((proxy, index) => {
                const label = describeProxy(proxy, index);
                const dialerProxy = text(proxy && proxy['dialer-proxy']);
                const proxyType = text(proxy && proxy.type);
                const hasAlternativePortSpec = (
                    (proxyType === 'hysteria2' && isValidPortListValue(proxy && proxy.ports))
                    || (proxyType === 'mieru' && isValidPortValue(proxy && proxy['port-range']))
                );

                if (!hasText(proxy && proxy.name)) {
                    pushIssue('error', `${label} 缺少名称。`);
                }
                if (!hasText(proxy && proxy.server)) {
                    pushIssue('error', `${label} 缺少 server。`);
                }
                if (!hasAlternativePortSpec && !isValidPortValue(proxy && proxy.port)) {
                    pushIssue('error', `${label} 的 port 不能为空，且必须是有效端口或端口范围。`);
                }
                if (dialerProxy && !validDialerTargets.has(dialerProxy)) {
                    pushIssue('error', `${label} 的 dialer-proxy 引用了不存在的代理/策略组 "${dialerProxy}"。`);
                }

                const proxyIssues = typeof getProxyValidationIssues === 'function' ? getProxyValidationIssues(proxy) : [];
                proxyIssues.forEach((issue) => {
                    if (!issue || !issue.message) return;
                    pushIssue(issue.level === 'warning' ? 'warning' : 'error', `${label}: ${issue.message}`);
                });
            });

            listeners.forEach((listener, index) => {
                const label = describeListener(listener, index);
                const type = text(listener && listener.type) || 'mixed';
                const proxyRef = text(listener && listener.proxy);
                const ruleRef = text(listener && listener.rule);

                if (!hasText(listener && listener.name)) {
                    pushIssue('error', `${label} 缺少名称。`);
                }
                if (!isValidPortListValue(listener && listener.port)) {
                    pushIssue('error', `${label} 的 port 不能为空，且必须是有效端口或端口范围。`);
                }
                if (proxyRef && !validDialerTargets.has(proxyRef)) {
                    pushIssue('error', `${label} 的 proxy 引用了不存在的代理/策略组 "${proxyRef}"。`);
                }
                if (ruleRef && subRuleParseOk && !subRuleNames.has(ruleRef)) {
                    pushIssue('error', `${label} 的 rule 引用了不存在的子规则 "${ruleRef}"。`);
                }

                if (!SUPPORTED_SIMPLE_LISTENER_TYPES.has(type)) {
                    pushIssue('warning', `${label} 使用了当前编辑器未完整支持的 listener 类型 "${type}"；协议私有字段会按原样保留，但不会参与细项校验。`);
                    return;
                }

                if (['mixed', 'http', 'socks'].includes(type)) {
                    let users = Array.isArray(listener && listener.users) ? listener.users : [];
                    const usersText = text(listener && listener._usersText);
                    if (usersText) {
                        try {
                            users = parseListenerUsersText(usersText);
                        } catch (err) {
                            pushIssue('error', `${label} 的 users 无法解析：${err.message}`);
                            users = [];
                        }
                    }

                    if (users.length > 0) {
                        validateListenerUsers(users, label, pushIssue);
                    }

                    const certificate = text(listener && listener.certificate);
                    const privateKey = text(listener && listener['private-key']);
                    const clientAuthType = text(listener && listener['client-auth-type']);
                    const clientAuthCert = text(listener && listener['client-auth-cert']);
                    const echKey = text(listener && listener['ech-key']);
                    const echCert = text(listener && listener['ech-cert']);
                    const hasTlsIdentity = !!certificate || !!privateKey;

                    if (!!certificate !== !!privateKey) {
                        pushIssue('error', `${label} 的 certificate 和 private-key 必须成对填写。`);
                    }
                    if (clientAuthType && !SUPPORTED_LISTENER_CLIENT_AUTH_TYPES.has(clientAuthType)) {
                        pushIssue('error', `${label} 的 client-auth-type "${clientAuthType}" 不在官方支持列表中。`);
                    }
                    if (clientAuthType === 'skip') {
                        pushIssue('warning', `${label} 使用了 client-auth-type=skip；当前官方文档更常见的写法是 request。`);
                    }
                    if ((clientAuthType || clientAuthCert || echKey || echCert) && !hasTlsIdentity) {
                        pushIssue('error', `${label} 配置 TLS/mTLS/ECH 相关字段时，必须同时填写 certificate 和 private-key。`);
                    }
                    if (['verify-if-given', 'require-and-verify'].includes(clientAuthType) && !clientAuthCert) {
                        pushIssue('error', `${label} 的 client-auth-type=${clientAuthType} 时必须填写 client-auth-cert。`);
                    }
                    if (!clientAuthType && clientAuthCert) {
                        pushIssue('warning', `${label} 填写了 client-auth-cert，但未设置 client-auth-type。`);
                    }
                    if (['request', 'skip', 'require-any'].includes(clientAuthType) && clientAuthCert) {
                        pushIssue('warning', `${label} 的 client-auth-type=${clientAuthType} 通常不会使用 client-auth-cert。`);
                    }
                    if (!!echKey !== !!echCert) {
                        pushIssue('warning', `${label} 的 ech-key 和 ech-cert 建议成对填写。`);
                    }
                }

                if (type === 'shadowsocks') {
                    const cipher = text(listener && listener.cipher);
                    const password = text(listener && listener.password);

                    if (!cipher) {
                        pushIssue('error', `${label} 的 shadowsocks listener 缺少 cipher。`);
                    } else if (!SUPPORTED_LISTENER_SHADOWSOCKS_CIPHERS.has(cipher)) {
                        pushIssue('error', `${label} 的 shadowsocks listener 使用了当前编辑器未纳入官方列表的 cipher "${cipher}"。`);
                    }

                    if (cipher && shadowsocksCipherRequiresPassword(cipher) && !password) {
                        pushIssue('error', `${label} 的 shadowsocks listener 缺少 password。`);
                    }
                    if (cipher === 'none' && password) {
                        pushIssue('warning', `${label} 的 shadowsocks listener 使用 cipher=none 时通常不需要填写 password。`);
                    }
                    const expectedKeyBytes = getShadowsocks2022KeyBytes(cipher);
                    if (expectedKeyBytes && password && !isValidShadowsocksPasswordForCipher(cipher, password)) {
                        pushIssue('error', `${label} 使用 ${cipher} 时，password 必须是 ${expectedKeyBytes} 字节随机密钥的 Base64 编码。`);
                    }

                    const shadowTlsText = text(listener && listener._shadowTlsText);
                    const kcpTunText = text(listener && listener._kcpTunText);

                    if (shadowTlsText) {
                        try {
                            const parsed = parseYamlObjectText(shadowTlsText);
                            if (!isPlainObject(parsed)) {
                                pushIssue('error', `${label} 的 shadow-tls 必须是 YAML/JSON 对象。`);
                            }
                        } catch (err) {
                            pushIssue('error', `${label} 的 shadow-tls 无法解析：${err.message}`);
                        }
                    }

                    if (kcpTunText) {
                        try {
                            const parsed = parseYamlObjectText(kcpTunText);
                            if (!isPlainObject(parsed)) {
                                pushIssue('error', `${label} 的 kcp-tun 必须是 YAML/JSON 对象。`);
                            }
                        } catch (err) {
                            pushIssue('error', `${label} 的 kcp-tun 无法解析：${err.message}`);
                        }
                    }
                }

                if (type === 'tunnel') {
                    const rawTunnelNetworks = Array.isArray(listener && listener.network)
                        ? listener.network
                        : String(listener?.network ?? '')
                            .split(/[\/,\s]+/)
                            .map((item) => item.trim())
                            .filter(Boolean);
                    const tunnelNetworks = normalizeTunnelListenerNetwork(listener && listener.network);

                    if (rawTunnelNetworks.length === 0 || tunnelNetworks.length === 0) {
                        pushIssue('error', `${label} 的 tunnel listener 至少需要选择一个 network。`);
                    }
                    rawTunnelNetworks.forEach((network) => {
                        if (!SUPPORTED_TUNNEL_LISTENER_NETWORKS.has(String(network || '').trim().toLowerCase())) {
                            pushIssue('error', `${label} 的 tunnel listener 使用了不支持的 network "${network}"。`);
                        }
                    });
                    if (!hasText(listener && listener.target)) {
                        pushIssue('error', `${label} 的 tunnel listener 缺少 target。`);
                    }
                }
            });

            const portEntries = [];
            const addPortEntry = (label, value) => {
                const parsed = parsePortSpec(value);
                if (!parsed) return;
                portEntries.push({
                    label,
                    value: text(value),
                    ranges: parsed
                });
            };

            addPortEntry('基础混合端口 mixed-port', config.value && config.value['mixed-port']);
            addPortEntry('基础 HTTP 端口 port', config.value && config.value.port);
            addPortEntry('基础 SOCKS 端口 socks-port', config.value && config.value['socks-port']);
            addPortEntry('基础 Redir 端口 redir-port', config.value && config.value['redir-port']);
            const hasExplicitTproxyListener = listeners.some((listener) => text(listener && listener.type) === 'tproxy');
            if (uiState.value && uiState.value.tproxyEnable && !hasExplicitTproxyListener) {
                addPortEntry('基础 TProxy 端口 tproxy-port', config.value && config.value['tproxy-port']);
            }
            listeners.forEach((listener, index) => {
                const effectivePort = (uiState.value && uiState.value.tproxyEnable && text(listener && listener.type) === 'tproxy')
                    ? (config.value && config.value['tproxy-port'])
                    : (listener && listener.port);
                addPortEntry(describeListener(listener, index), effectivePort);
            });

            for (let i = 0; i < portEntries.length; i += 1) {
                for (let j = i + 1; j < portEntries.length; j += 1) {
                    const first = portEntries[i];
                    const second = portEntries[j];
                    const overlap = getPortSpecOverlap(first.ranges, second.ranges);
                    if (!overlap) continue;
                    pushIssue('error', `${first.label} 与 ${second.label} 端口冲突：${formatPortOverlap(overlap)}。`);
                }
            }

            const subscriptionSources = new Map();
            providers.forEach((provider) => {
                if (!provider || provider._chainMode) return;
                const name = text(provider.name);
                if (!name || subscriptionSources.has(name)) return;
                subscriptionSources.set(name, provider);
            });

            providers.forEach((provider, index) => {
                const label = describeProvider(provider, index);
                const name = text(provider && provider.name);
                const type = text(provider && provider.type) || 'http';
                const chainMode = text(provider && provider._chainMode);
                const sourceProviderName = text(provider && provider._sourceProviderName);
                const downloadProxy = text((provider && provider.proxy) || (provider && provider.downloadProxy));
                const ageSecretKey = text(provider && provider.ageSecretKey);
                const overrideDialerProxy = text(provider && provider.overrideDialerProxy);
                const overrideUdp = text(provider && provider.overrideUdp).toLowerCase();
                const overrideUdpOverTcp = text(provider && provider.overrideUdpOverTcp).toLowerCase();
                const overrideTfo = text(provider && provider.overrideTfo).toLowerCase();
                const overrideMptcp = text(provider && provider.overrideMptcp).toLowerCase();
                const overrideSkipCertVerify = text(provider && provider.overrideSkipCertVerify).toLowerCase();
                const overrideUp = text(provider && provider.overrideUp);
                const overrideDown = text(provider && provider.overrideDown);
                const overrideInterfaceName = text(provider && provider.overrideInterfaceName);
                const overrideRoutingMark = text(provider && provider.overrideRoutingMark);
                const overrideIpVersion = text(provider && provider.overrideIpVersion);
                const inlineProxies = Array.isArray(provider && provider.inlineProxies)
                    ? provider.inlineProxies.map((item) => text(item)).filter(Boolean)
                    : [];
                const fallbackPayloadProxies = Array.isArray(provider && provider._fallbackPayloadProxyNames)
                    ? provider._fallbackPayloadProxyNames.map((item) => text(item)).filter(Boolean)
                    : [];
                const detachedFallbackPayloadProxies = unique(
                    fallbackPayloadProxies.filter((proxyName) => !proxyNameSet.has(proxyName))
                );
                const unsupportedOverrideKeys = Array.isArray(provider && provider._unsupportedOverrideKeys)
                    ? provider._unsupportedOverrideKeys.map((item) => text(item)).filter(Boolean)
                    : [];

                if (!name) {
                    pushIssue('error', `${label} 缺少名称。`);
                }
                if (!SUPPORTED_PROXY_PROVIDER_TYPES.has(type)) {
                    pushIssue('error', `${label} 使用了当前编辑器未完整支持的 provider 类型 "${type}"。`);
                }
                if (downloadProxy && !validDialerTargets.has(downloadProxy)) {
                    pushIssue('error', `${label} 的 proxy 引用了不存在的代理/策略组 "${downloadProxy}"。`);
                }
                if (overrideDialerProxy && !validDialerTargets.has(overrideDialerProxy)) {
                    pushIssue('error', `${label} 的 override.dialer-proxy 引用了不存在的代理/策略组 "${overrideDialerProxy}"。`);
                }
                if (type === 'http' && hasText(provider && provider.url) && !isValidAbsoluteUrl(provider && provider.url)) {
                    pushIssue('error', `${label} 的 url 不是有效的绝对 URL。`);
                }
                if (text(provider && provider.sizeLimit) && !isValidNonNegativeNumberText(provider && provider.sizeLimit)) {
                    pushIssue('error', `${label} 的 size-limit 必须是大于等于 0 的数字。`);
                }
                if (ageSecretKey && !ageSecretKey.startsWith('AGE-SECRET-KEY-')) {
                    pushIssue('warning', `${label} 的 age-secret-key 通常应以 AGE-SECRET-KEY- 开头。`);
                }
                validateYamlHeaders(provider && provider.headers, label, pushIssue);
                validateProxyNameOverride(provider && provider.overrideProxyName, label, pushIssue);
                if (!isValidTriStateBooleanText(overrideUdp)) {
                    pushIssue('error', `${label} 的 override.udp 只能是 true / false / 空。`);
                }
                if (!isValidTriStateBooleanText(overrideUdpOverTcp)) {
                    pushIssue('error', `${label} 的 override.udp-over-tcp 只能是 true / false / 空。`);
                }
                if (!isValidTriStateBooleanText(overrideTfo)) {
                    pushIssue('error', `${label} 的 override.tfo 只能是 true / false / 空。`);
                }
                if (!isValidTriStateBooleanText(overrideMptcp)) {
                    pushIssue('error', `${label} 的 override.mptcp 只能是 true / false / 空。`);
                }
                if (!isValidTriStateBooleanText(overrideSkipCertVerify)) {
                    pushIssue('error', `${label} 的 override.skip-cert-verify 只能是 true / false / 空。`);
                }
                if (overrideIpVersion && !IP_VERSION_OPTIONS.has(overrideIpVersion)) {
                    pushIssue('error', `${label} 的 override.ip-version 不在官方支持列表中。`);
                }
                if (!isValidRoutingMarkText(overrideRoutingMark)) {
                    pushIssue('error', `${label} 的 override.routing-mark 必须是十进制或 0x 十六进制整数。`);
                }
                if (!!overrideUp !== !!overrideDown) {
                    pushIssue('warning', `${label} 的 override.up 和 override.down 建议成对填写。`);
                }
                if (overrideInterfaceName && /\s/.test(overrideInterfaceName)) {
                    pushIssue('warning', `${label} 的 override.interface-name 含有空白字符，请确认网卡名拼写。`);
                }

                if (unsupportedOverrideKeys.length > 0) {
                    pushIssue('warning', `${label} 含有当前编辑器暂不可直接编辑的 override 字段：${unsupportedOverrideKeys.join(', ')}；导出时会按原样保留。`);
                }
                if (detachedFallbackPayloadProxies.length > 0 && ['http', 'file'].includes(type)) {
                    pushIssue('warning', `${label} 的 payload fallback 包含当前节点列表中不存在的快照节点：${detachedFallbackPayloadProxies.join(', ')}；导出时会按原样保留。`);
                }

                if (chainMode === 'provider') {
                    if (!sourceProviderName) {
                        pushIssue('error', `${label} 处于 provider chain 模式时，必须选择来源提供者。`);
                    } else if (sourceProviderName === name) {
                        pushIssue('error', `${label} 的来源提供者不能指向自己。`);
                    } else {
                        const sourceProvider = subscriptionSources.get(sourceProviderName);
                        if (!sourceProvider) {
                            pushIssue('error', `${label} 的来源提供者 "${sourceProviderName}" 不存在。`);
                        } else {
                            const sourceType = text(sourceProvider.type) || 'http';
                            if (!['http', 'file'].includes(sourceType)) {
                                pushIssue('error', `${label} 的来源提供者 "${sourceProviderName}" 必须是 http 或 file 类型。`);
                            }
                        }
                    }
                } else if (type === 'http' && !hasText(provider && provider.url)) {
                        pushIssue('error', `${label} 使用 http 类型时必须填写 url。`);
                }

                if (type === 'inline') {
                    const missingInlineProxies = unique(inlineProxies.filter((proxyName) => !proxyNameSet.has(proxyName)));
                    if (missingInlineProxies.length > 0) {
                        pushIssue('error', `${label} 的 inline payload 引用了不存在的节点：${missingInlineProxies.join(', ')}`);
                    }
                    if (inlineProxies.length === 0) {
                        pushIssue('warning', `${label} 的 inline payload 为空。`);
                    }
                }

                if (['http', 'file'].includes(type)) {
                    if (type === 'http' && !isValidPositiveNumber(provider && provider.interval)) {
                        pushIssue('warning', `${label} 的 interval 无效；导出时会回退到默认值。`);
                    }

                    if (provider && provider.healthCheckEnable !== false) {
                        if (!hasText(provider && provider.healthUrl)) {
                            pushIssue('warning', `${label} 未填写 health-check.url；导出时会回退到默认测速地址。`);
                        } else if (!isValidAbsoluteUrl(provider && provider.healthUrl)) {
                            pushIssue('warning', `${label} 的 health-check.url 不是有效的绝对 URL。`);
                        }
                        if (!isValidPositiveNumber(provider && provider.healthCheckInterval)) {
                            pushIssue('warning', `${label} 的 health-check.interval 无效；导出时会回退到默认值。`);
                        }
                        if (!isValidPositiveNumber(provider && provider.healthCheckTimeout)) {
                            pushIssue('warning', `${label} 的 health-check.timeout 无效；导出时会回退到默认值。`);
                        }
                    }
                }
            });

            ruleProviders.forEach((provider, index) => {
                const label = describeRuleProvider(provider, index);
                const name = text(provider && provider.name);
                const type = text(provider && provider.type) || 'http';
                const behavior = text(provider && provider.behavior) || 'domain';
                const format = text(provider && provider.format) || 'mrs';
                const proxyRef = text(provider && provider.proxy);
                const pathInBundle = text(provider && provider.pathInBundle);

                if (!name) {
                    pushIssue('error', `${label} 缺少名称。`);
                }
                if (!SUPPORTED_RULE_PROVIDER_TYPES.has(type)) {
                    pushIssue('error', `${label} 使用了当前编辑器未完整支持的规则集类型 "${type}"。`);
                }
                if (!SUPPORTED_RULE_PROVIDER_BEHAVIORS.has(behavior)) {
                    pushIssue('error', `${label} 的 behavior "${behavior}" 不在官方支持列表中。`);
                }
                if (type !== 'inline' && !SUPPORTED_RULE_PROVIDER_FORMATS.has(format)) {
                    pushIssue('error', `${label} 的 format "${format}" 不在官方支持列表中。`);
                }
                if (type !== 'inline' && format === 'mrs' && behavior === 'classical') {
                    pushIssue('error', `${label} 的 classical 行为不支持 mrs 格式。`);
                }
                if (type === 'http') {
                    const url = text(provider && provider.autoUrl ? getRuleProviderUrl(provider) : provider && provider.customUrl);
                    if (!url) {
                        pushIssue('error', `${label} 使用 http 类型时必须填写可解析的 URL。`);
                    } else if (!isValidAbsoluteUrl(url)) {
                        pushIssue('error', `${label} 的 URL 不是有效的绝对 URL。`);
                    }
                    if (provider && provider.autoUrl && behavior === 'classical') {
                        pushIssue('error', `${label} 的 classical 行为不能使用自动补全 URL。`);
                    }
                    if (!isValidPositiveNumber(provider && provider.interval)) {
                        pushIssue('warning', `${label} 的 interval 无效；导出时会回退到默认值。`);
                    }
                    validateYamlHeaders(provider && provider.headers, label, pushIssue);
                }
                if (proxyRef && !validDialerTargets.has(proxyRef)) {
                    pushIssue('error', `${label} 的 proxy 引用了不存在的代理/策略组 "${proxyRef}"。`);
                }
                if (text(provider && provider.sizeLimit) && !isValidNonNegativeNumberText(provider && provider.sizeLimit)) {
                    pushIssue('error', `${label} 的 size-limit 必须是大于等于 0 的数字。`);
                }
                if (type === 'inline' && splitLines(provider && provider.payload).length === 0) {
                    pushIssue('warning', `${label} 的 inline payload 为空。`);
                }
                if (type === 'inline' && pathInBundle) {
                    pushIssue('warning', `${label} 是 inline 类型，path-in-bundle 不会导出。`);
                }
                if (pathInBundle && /^[/\\]/.test(pathInBundle)) {
                    pushIssue('warning', `${label} 的 path-in-bundle 通常应填写包内相对路径。`);
                }
            });

            if (dns && dns.enable) {
                const dnsListen = text(dns.listen || ':53');
                const defaultNameservers = splitLines(uiState.value && uiState.value.dnsDefaultNameservers);
                const nameservers = splitLines(uiState.value && uiState.value.dnsNameservers);
                const fallbackNameservers = splitLines(uiState.value && uiState.value.enableDnsFallback ? uiState.value.dnsFallback : '');
                const proxyServerNameservers = splitLines(uiState.value && uiState.value.dnsProxyServerNameservers);
                const directNameservers = splitLines(uiState.value && uiState.value.dnsDirectNameservers);
                const nameserverPolicyText = text(uiState.value && uiState.value.dnsNameserverPolicy);
                const proxyServerNameserverPolicyText = text(uiState.value && uiState.value.dnsProxyServerNameserverPolicy);
                const fakeIpFilterLines = splitLines(uiState.value && uiState.value.fakeIpFilter);

                if (!isValidListenAddress(dnsListen)) {
                    pushIssue('error', `DNS.listen "${dnsListen || '(空)'}" 不是有效的监听地址/端口。`);
                }
                if (text(dns['cache-max-size']) && !isValidNonNegativeNumberText(dns['cache-max-size'])) {
                    pushIssue('error', 'DNS.cache-max-size 必须是大于等于 0 的数字。');
                }
                if (dns.ipv6 && text(dns['ipv6-timeout']) && !isValidNonNegativeNumberText(dns['ipv6-timeout'])) {
                    pushIssue('error', 'DNS.ipv6-timeout 必须是大于等于 0 的数字。');
                }

                const bootstrapSources = [];
                const dnsValidationContext = {
                    validDnsRouteTargets,
                    knownInterfaceNames
                };
                const defaultNameserverResult = validateDnsServerList(defaultNameservers, 'default-nameserver', pushIssue, {
                    allowBootstrapHostname: false,
                    ...dnsValidationContext
                });
                const nameserverResult = validateDnsServerList(nameservers, 'nameserver', pushIssue, {
                    allowBootstrapHostname: true,
                    ...dnsValidationContext
                });
                const fallbackResult = validateDnsServerList(fallbackNameservers, 'fallback', pushIssue, {
                    allowBootstrapHostname: true,
                    ...dnsValidationContext
                });
                const proxyServerResult = validateDnsServerList(proxyServerNameservers, 'proxy-server-nameserver', pushIssue, {
                    allowBootstrapHostname: true,
                    ...dnsValidationContext
                });
                const directNameserverResult = validateDnsServerList(directNameservers, 'direct-nameserver', pushIssue, {
                    allowBootstrapHostname: true,
                    ...dnsValidationContext
                });
                bootstrapSources.push(...nameserverResult.entries);
                bootstrapSources.push(...fallbackResult.entries);
                bootstrapSources.push(...proxyServerResult.entries);
                bootstrapSources.push(...directNameserverResult.entries);

                const nameserverPolicyResult = validateDnsPolicyMap(nameserverPolicyText, 'nameserver-policy', ruleProviderNameSet, pushIssue, dnsValidationContext);
                const proxyServerPolicyResult = validateDnsPolicyMap(proxyServerNameserverPolicyText, 'proxy-server-nameserver-policy', ruleProviderNameSet, pushIssue, dnsValidationContext);
                bootstrapSources.push(...nameserverPolicyResult.entries);
                bootstrapSources.push(...proxyServerPolicyResult.entries);

                if (unique(bootstrapSources).length > 0 && defaultNameservers.length === 0) {
                    pushIssue('error', '当前 DNS 配置包含基于域名的上游服务器，但 default-nameserver 为空，无法完成引导解析。');
                }

                if (dns['respect-rules'] && proxyServerNameservers.length === 0) {
                    pushIssue('error', '开启 respect-rules 时必须配置 proxy-server-nameserver。');
                }
                if ((defaultNameserverResult.usesRules || nameserverResult.usesRules || fallbackResult.usesRules || proxyServerResult.usesRules || directNameserverResult.usesRules || nameserverPolicyResult.usesRules || proxyServerPolicyResult.usesRules) && proxyServerNameservers.length === 0) {
                    pushIssue('warning', '存在使用 #RULES 的 DNS 服务器，但 proxy-server-nameserver 为空；官方文档建议补齐以避免规则链路解析问题。');
                }
                if (dns['respect-rules'] && dns['prefer-h3']) {
                    pushIssue('warning', 'prefer-h3 与 respect-rules 同时开启时，官方文档提示可能无法自动遵守 rules 选择链路。');
                }
                if (dns['direct-nameserver-follow-policy'] && directNameservers.length === 0) {
                    pushIssue('warning', 'direct-nameserver-follow-policy 已开启，但 direct-nameserver 为空，不会生效。');
                }
                if (dns['direct-nameserver-follow-policy'] && !nameserverPolicyText) {
                    pushIssue('warning', 'direct-nameserver-follow-policy 已开启，但 nameserver-policy 为空，没有策略可跟随。');
                }
                if (proxyServerNameserverPolicyText && !uiState.value.enableProxyServerNameserverPolicy) {
                    pushIssue('warning', 'proxy-server-nameserver-policy 文本存在，但当前开关未启用，导出时不会生效。');
                }
                if (proxyServerNameserverPolicyText && proxyServerNameservers.length === 0) {
                    pushIssue('warning', '配置了 proxy-server-nameserver-policy，但 proxy-server-nameserver 为空，不会生效。');
                }
                if (uiState.value.enableDnsFallback && fallbackNameservers.length === 0) {
                    pushIssue('warning', '已启用 fallback，但 fallback 列表为空，导出时不会生成 fallback。');
                }
                if (uiState.value.enableDnsFallback && fallbackNameservers.length > 0) {
                    const fallbackFilter = isPlainObject(dns['fallback-filter']) ? dns['fallback-filter'] : {};
                    const hasGeoip = fallbackFilter.geoip !== false;
                    const geoipCode = text(fallbackFilter['geoip-code'] || '');
                    const geositeList = uiState.value.fallbackFilterGeositeEnable ? splitLines(uiState.value.fallbackFilterGeosite) : [];
                    const ipcidrList = splitLines(uiState.value.fallbackFilterIpcidr);
                    const domainList = splitLines(uiState.value.fallbackFilterDomain);

                    if (hasGeoip && !geoipCode) {
                        pushIssue('warning', 'fallback-filter 开启了 geoip，但 geoip-code 为空；导出时会回退到默认 CN。');
                    }
                    if (!hasGeoip && geositeList.length === 0 && ipcidrList.length === 0 && domainList.length === 0) {
                        pushIssue('warning', 'fallback 已启用，但 fallback-filter 没有任何筛选条件，可能导致 fallback 结果全部参与。');
                    }
                }
                if (dns['enhanced-mode'] === 'fake-ip' && text(dns['fake-ip-filter-mode']).toLowerCase() === 'rule') {
                    if (fakeIpFilterLines.length === 0) {
                        pushIssue('warning', 'fake-ip-filter-mode=rule 时，fake-ip-filter 为空。');
                    } else {
                        validateFakeIpRuleLines(fakeIpFilterLines, 'fake-ip-filter', ruleProviderNameSet, pushIssue);
                    }
                }
            }

            proxyGroups.forEach((group, index) => {
                const label = describeGroup(group, index);
                const name = text(group && group.name);
                const type = text(group && group.type) || 'select';
                const proxiesInGroup = Array.isArray(group && group.proxies)
                    ? group.proxies.map((item) => text(item)).filter(Boolean)
                    : [];
                const useProviders = Array.isArray(group && group.use)
                    ? group.use.map((item) => text(item)).filter(Boolean)
                    : [];
                const missingMembers = unique(
                    proxiesInGroup.filter((memberName) => memberName !== name && !validRuleTargets.has(memberName))
                );
                const missingProviders = unique(useProviders.filter((providerName) => !providerNameSet.has(providerName)));
                const includeAll = !!(group && group['include-all'] && type !== 'relay');
                const includeAllProxies = !!(group && !includeAll && group['include-all-proxies']);
                const includeAllProviders = !!(group && !includeAll && group['include-all-providers']);
                const emptyFallback = text(group && group['empty-fallback']);
                const reliesOnlyOnProviderMembers = URL_TEST_GROUP_TYPES.has(type)
                    && !includeAll
                    && !includeAllProxies
                    && proxiesInGroup.length === 0
                    && (includeAllProviders || useProviders.length > 0);

                if (!name) {
                    pushIssue('error', `${label} 缺少名称。`);
                }
                if (!SUPPORTED_PROXY_GROUP_TYPES.has(type)) {
                    pushIssue('error', `${label} 使用了当前编辑器未完整支持的策略组类型 "${type}"。`);
                }
                if (name && proxiesInGroup.includes(name)) {
                    pushIssue('error', `${label} 不能把自己加入 proxies。`);
                }
                if (missingMembers.length > 0) {
                    pushIssue('error', `${label} 的 proxies 引用了不存在的节点/策略组：${missingMembers.join(', ')}`);
                }
                if (missingProviders.length > 0) {
                    pushIssue('error', `${label} 的 use 引用了不存在的代理提供者：${missingProviders.join(', ')}`);
                }
                const validEmptyFallbackTargets = new Set([...BUILTIN_RULE_TARGETS, ...proxyNames]);
                if (emptyFallback && !validEmptyFallbackTargets.has(emptyFallback)) {
                    pushIssue('error', `${label} 的 empty-fallback 必须引用内建代理或手动节点，当前目标不存在或不是可用代理："${emptyFallback}"。`);
                }
                if (group && group['include-all'] && group['include-all-proxies']) {
                    pushIssue('warning', `${label} 同时开启了 include-all 和 include-all-proxies；导出时会以 include-all 为准。`);
                }
                if (group && group['include-all'] && group['include-all-providers']) {
                    pushIssue('warning', `${label} 同时开启了 include-all 和 include-all-providers；导出时会以 include-all 为准。`);
                }
                if (group && group['include-all-providers'] && useProviders.length > 0) {
                    pushIssue('warning', `${label} 同时填写了 use 与 include-all-providers；导出时会以 include-all-providers 为准。`);
                }
                if (hasText(group && group['exclude-type']) && /[\\^$*+?.()[\]{}]/.test(text(group['exclude-type']))) {
                    pushIssue('warning', `${label} 的 exclude-type 按官方文档应为以 | 分隔的类型列表，不是正则表达式。`);
                }
                if (type === 'relay' && proxiesInGroup.length === 0) {
                    pushIssue('error', `${label} 是 relay 类型，但 proxies 为空。`);
                }
                if (type === 'relay') {
                    pushIssue('warning', `${label} 使用了 relay；官方文档已标注该组型即将废弃。`);
                    if (proxiesInGroup.length === 1) {
                        pushIssue('warning', `${label} 只有一个成员，relay 链路通常至少需要两个节点。`);
                    }
                    const relayWireGuardMembers = proxiesInGroup.filter((memberName) => {
                        const proxy = proxyByName.get(memberName);
                        return proxy && text(proxy.type) === 'wireguard';
                    });
                    if (relayWireGuardMembers.length > 0) {
                        pushIssue('error', `${label} 的 relay 链路包含 WireGuard 节点，官方文档说明当前不支持。`);
                    }
                    if (!group['disable-udp'] && proxiesInGroup.length >= 2) {
                        const head = proxyByName.get(proxiesInGroup[0]);
                        const tail = proxyByName.get(proxiesInGroup[proxiesInGroup.length - 1]);
                        const headType = text(head && head.type);
                        const tailType = text(tail && tail.type);
                        if ((head && !RELAY_UDP_HEAD_TAIL_TYPES.has(headType)) || (tail && !RELAY_UDP_HEAD_TAIL_TYPES.has(tailType))) {
                            pushIssue('warning', `${label} 未关闭 UDP，但 relay 首尾节点并非官方说明中支持 UDP over TCP 的类型，UDP 中继可能不可用。`);
                        }
                    }
                }
                if (URL_TEST_GROUP_TYPES.has(type) && !hasText(group && group.url)) {
                    pushIssue('warning', `${label} 未填写 url；导出时会回退到默认测速地址。`);
                }
                if (URL_TEST_GROUP_TYPES.has(type) && hasText(group && group.url) && !isValidAbsoluteUrl(group && group.url)) {
                    pushIssue('error', `${label} 的 url 不是有效的绝对 URL。`);
                }
                if (URL_TEST_GROUP_TYPES.has(type) && text(group && group['expected-status']) && !validateExpectedStatus(group && group['expected-status'])) {
                    pushIssue('error', `${label} 的 expected-status 语法无效，应为 * 或以 / 分隔的状态码/区间。`);
                }
                if (URL_TEST_GROUP_TYPES.has(type) && reliesOnlyOnProviderMembers) {
                    pushIssue('warning', `${label} 仅通过 use / include-all-providers 引入成员；官方文档说明 url-test/fallback/load-balance 的 url 只会检查 proxies 字段中的节点。`);
                }
                if (URL_TEST_GROUP_TYPES.has(type) && hasText(group && group['max-failed-times']) && Number(group['max-failed-times']) < 0) {
                    pushIssue('error', `${label} 的 max-failed-times 不能小于 0。`);
                }
                if (type === 'load-balance' && hasText(group && group.strategy) && !LOAD_BALANCE_STRATEGY_OPTIONS.has(text(group && group.strategy))) {
                    pushIssue('error', `${label} 的 strategy "${text(group && group.strategy)}" 不在官方支持列表中。`);
                }
                if (hasText(group && group['interface-name'])) {
                    pushIssue('warning', `${label} 使用了官方已标注 deprecated 的 interface-name。`);
                }
                if (hasText(group && group['routing-mark'])) {
                    pushIssue('warning', `${label} 使用了官方已标注 deprecated 的 routing-mark。`);
                }
            });

            rules.forEach((rule, index) => {
                const label = describeRule(rule, index);

                if (rule && rule.logic) {
                    const target = text(rule.target);
                    const conditions = Array.isArray(rule.conditions) ? rule.conditions : [];

                    if (!target) {
                        pushIssue('error', `${label} 缺少 target。`);
                    } else if (!validRuleTargets.has(target)) {
                        pushIssue('error', `${label} 的 target 指向了不存在的节点/策略组 "${target}"。`);
                    }
                    if (conditions.length === 0) {
                        pushIssue('error', `${label} 至少需要一个子条件。`);
                    }

                    conditions.forEach((condition, conditionIndex) => {
                        if (!condition || text(condition.type) !== 'RULE-SET') return;

                        const ref = text(condition.value);
                        if (!ref) {
                            pushIssue('error', `${label} 的第 ${conditionIndex + 1} 个条件缺少 RULE-SET 引用名称。`);
                        } else if (!ruleProviderNameSet.has(ref)) {
                            pushIssue('error', `${label} 的第 ${conditionIndex + 1} 个条件引用了不存在的规则集 "${ref}"。`);
                        }
                    });
                    return;
                }

                const type = text(rule && rule.type);
                const target = text(rule && rule.target);

                if (!type) {
                    pushIssue('error', `${label} 缺少类型。`);
                    return;
                }

                if (type === 'SUB-RULE') {
                    if (!target) {
                        pushIssue('error', `${label} 缺少子规则名称。`);
                    } else if (subRuleParseOk && !subRuleNames.has(target)) {
                        pushIssue('error', `${label} 引用了不存在的子规则 "${target}"。`);
                    }
                    return;
                }

                if (!target) {
                    pushIssue('error', `${label} 缺少 target。`);
                } else if (!validRuleTargets.has(target)) {
                    pushIssue('error', `${label} 的 target 指向了不存在的节点/策略组 "${target}"。`);
                }

                if (type === 'RULE-SET') {
                    const ref = text(rule && rule.value);
                    if (!ref) {
                        pushIssue('error', `${label} 缺少 RULE-SET 引用名称。`);
                    } else if (!ruleProviderNameSet.has(ref)) {
                        pushIssue('error', `${label} 引用了不存在的规则集 "${ref}"。`);
                    }
                }
            });

            return issues;
        });

        const runtimeValidationErrors = computed(() => runtimeValidationIssues.value
            .filter((issue) => issue.level === 'error')
            .map((issue) => issue.message));
        const runtimeValidationWarnings = computed(() => runtimeValidationIssues.value
            .filter((issue) => issue.level === 'warning')
            .map((issue) => issue.message));

        return {
            runtimeValidationIssues,
            runtimeValidationErrors,
            runtimeValidationWarnings
        };
    };
})(window);
