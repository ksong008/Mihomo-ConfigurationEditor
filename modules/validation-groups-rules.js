(function (window) {
    'use strict';

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createValidationGroupsRules = function (options = {}) {
        const {
            unique,
            text,
            hasText,
            isValidAbsoluteUrl,
            validateExpectedStatus
        } = options;

        const URL_TEST_GROUP_TYPES = new Set(['url-test', 'fallback', 'load-balance']);
        const SUPPORTED_PROXY_GROUP_TYPES = new Set(['select', 'url-test', 'fallback', 'load-balance']);
        const LOAD_BALANCE_STRATEGY_OPTIONS = new Set(['consistent-hashing', 'round-robin', 'sticky-sessions']);
        const RELAY_UDP_HEAD_TAIL_TYPES = new Set(['vmess', 'vless', 'trojan', 'ss', 'ssr', 'tuic']);

        const validateGroups = (runtimeOptions = {}) => {
            const {
                proxyGroups,
                proxyNames,
                proxyByName,
                providerNameSet,
                validRuleTargets,
                builtInRuleTargets,
                describeGroup,
                pushIssue
            } = runtimeOptions;

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
                const validEmptyFallbackTargets = new Set([...builtInRuleTargets, ...proxyNames]);
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
        };

        const validateRules = (runtimeOptions = {}) => {
            const {
                rules,
                subRuleParseOk,
                subRuleNames,
                ruleProviderNameSet,
                validRuleTargets,
                describeRule,
                pushIssue
            } = runtimeOptions;

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
        };

        return {
            validateGroups,
            validateRules
        };
    };
})(window);
