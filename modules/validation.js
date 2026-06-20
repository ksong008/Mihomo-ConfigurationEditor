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
        if (!window.MihomoFeatureModules.createValidationListeners) {
            throw new Error('ValidationListeners 未加载，请确认先引入 ./modules/validation-listeners.js');
        }
        if (!window.MihomoFeatureModules.createValidationProviders) {
            throw new Error('ValidationProviders 未加载，请确认先引入 ./modules/validation-providers.js');
        }
        if (!window.MihomoFeatureModules.createValidationGroupsRules) {
            throw new Error('ValidationGroupsRules 未加载，请确认先引入 ./modules/validation-groups-rules.js');
        }

        const BUILTIN_RULE_TARGETS = ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'COMPATIBLE'];
        const {
            validateDnsServerList,
            validateDnsPolicyMap,
            validateFakeIpRuleLines,
            validateExpectedStatus
        } = validationDns.createValidationDns({
            parseYamlMapText
        });
        const listenerValidation = window.MihomoFeatureModules.createValidationListeners({
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
        });
        const providerValidation = window.MihomoFeatureModules.createValidationProviders({
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
        });
        const groupRuleValidation = window.MihomoFeatureModules.createValidationGroupsRules({
            unique,
            text,
            hasText,
            isValidAbsoluteUrl,
            validateExpectedStatus
        });

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

            listenerValidation.validateListeners({
                listeners,
                validDialerTargets,
                subRuleNames,
                subRuleParseOk,
                describeListener,
                pushIssue
            });
            listenerValidation.validateListenerPortConflicts({
                config,
                uiState,
                listeners,
                describeListener,
                pushIssue
            });

            providerValidation.validateProviders({
                providers,
                proxyNameSet,
                validDialerTargets,
                describeProvider,
                pushIssue
            });
            providerValidation.validateRuleProviders({
                ruleProviders,
                validDialerTargets,
                describeRuleProvider,
                getRuleProviderUrl,
                pushIssue
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

            groupRuleValidation.validateGroups({
                proxyGroups,
                proxyNames,
                proxyByName,
                providerNameSet,
                validRuleTargets,
                builtInRuleTargets: BUILTIN_RULE_TARGETS,
                describeGroup,
                pushIssue
            });
            groupRuleValidation.validateRules({
                rules,
                subRuleParseOk,
                subRuleNames,
                ruleProviderNameSet,
                validRuleTargets,
                describeRule,
                pushIssue
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
