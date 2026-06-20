(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createValidationProviders = function (options = {}) {
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
            parseYamlMapText,
            parseYamlSequenceText
        } = options;

        const SUPPORTED_PROXY_PROVIDER_TYPES = new Set(['http', 'file', 'inline']);
        const SUPPORTED_RULE_PROVIDER_TYPES = new Set(['http', 'file', 'inline']);
        const SUPPORTED_RULE_PROVIDER_BEHAVIORS = new Set(['domain', 'ipcidr', 'classical']);
        const SUPPORTED_RULE_PROVIDER_FORMATS = new Set(['mrs', 'yaml', 'text']);
        const IP_VERSION_OPTIONS = new Set(['ipv4', 'ipv6', 'dual', 'ipv4-prefer', 'ipv6-prefer']);

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

        const validateProviders = (runtimeOptions = {}) => {
            const {
                providers,
                proxyNameSet,
                validDialerTargets,
                describeProvider,
                pushIssue
            } = runtimeOptions;

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
        };

        const validateRuleProviders = (runtimeOptions = {}) => {
            const {
                ruleProviders,
                validDialerTargets,
                describeRuleProvider,
                getRuleProviderUrl,
                pushIssue
            } = runtimeOptions;

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
        };

        return {
            validateProviders,
            validateRuleProviders
        };
    };
})(window);
