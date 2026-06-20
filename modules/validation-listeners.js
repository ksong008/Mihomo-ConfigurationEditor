(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createValidationListeners = function (options = {}) {
        const {
            text,
            hasText,
            isPlainObject,
            isValidPortListValue,
            parseYamlSequenceText,
            parseYamlObjectText,
            getShadowsocksCipherOptions,
            getShadowsocks2022KeyBytes,
            shadowsocksCipherRequiresPassword,
            isValidShadowsocksPasswordForCipher,
            normalizeTunnelListenerNetwork,
            parsePortSpec,
            getPortSpecOverlap,
            formatPortOverlap
        } = options;

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

        const validateListeners = (runtimeOptions = {}) => {
            const {
                listeners,
                validDialerTargets,
                subRuleNames,
                subRuleParseOk,
                describeListener,
                pushIssue
            } = runtimeOptions;

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
        };

        const validateListenerPortConflicts = (runtimeOptions = {}) => {
            const {
                config,
                uiState,
                listeners,
                describeListener,
                pushIssue
            } = runtimeOptions;
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

            for (let index = 0; index < portEntries.length; index += 1) {
                for (let nextIndex = index + 1; nextIndex < portEntries.length; nextIndex += 1) {
                    const first = portEntries[index];
                    const second = portEntries[nextIndex];
                    const overlap = getPortSpecOverlap(first.ranges, second.ranges);
                    if (!overlap) continue;
                    pushIssue('error', `${first.label} 与 ${second.label} 端口冲突：${formatPortOverlap(overlap)}。`);
                }
            }
        };

        return {
            validateListeners,
            validateListenerPortConflicts
        };
    };
})(window);
