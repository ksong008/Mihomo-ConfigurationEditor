(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createRulesModule = function (ctx) {
        const { ref, config, uiState, scrollToBottom } = ctx;
        const ruleParser = window.MihomoFeatureModules && window.MihomoFeatureModules.RuleParser;
        if (!ruleParser) {
            throw new Error('RuleParser 未加载，请确认先引入 ./modules/rule-parser.js');
        }
        const { formatConditions, parseRuleString } = ruleParser;
        const normalizeRuleOption = (option) => typeof option === 'string'
            ? { value: option, label: option }
            : option;
        const RULE_TYPE_GROUPS = [
            {
                label: '域名',
                options: ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX'].map(normalizeRuleOption)
            },
            {
                label: 'IP',
                options: ['IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'IP-SUFFIX', 'SRC-IP-SUFFIX', 'GEOIP', 'SRC-GEOIP', 'IP-ASN', 'SRC-IP-ASN'].map(normalizeRuleOption)
            },
            {
                label: '地理 / 进程',
                options: ['GEOSITE', 'PROCESS-NAME', 'PROCESS-NAME-REGEX', 'PROCESS-NAME-WILDCARD', 'PROCESS-PATH', 'PROCESS-PATH-REGEX', 'PROCESS-PATH-WILDCARD'].map(normalizeRuleOption)
            },
            {
                label: '端口 / 网络',
                options: ['DST-PORT', 'SRC-PORT', 'IN-PORT', 'IN-USER', 'IN-NAME', 'UID', 'DSCP', 'NETWORK'].map(normalizeRuleOption)
            },
            {
                label: '高级',
                options: [
                    { value: 'RULE-SET', label: 'RULE-SET (规则集引用)' },
                    { value: 'SUB-RULE', label: 'SUB-RULE' },
                    { value: 'IN-TYPE', label: 'IN-TYPE' },
                    { value: 'MATCH', label: 'MATCH (兜底)' }
                ]
            }
        ];
        const LOGIC_RULE_TYPE_GROUPS = RULE_TYPE_GROUPS
            .map((group) => ({
                ...group,
                options: group.options.filter((option) => option.value !== 'MATCH')
            }))
            .filter((group) => group.options.length > 0);
        const IP_RULE_TYPES = ['GEOIP', 'SRC-GEOIP', 'IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'IP-SUFFIX', 'IP-ASN', 'SRC-IP-SUFFIX', 'SRC-IP-ASN'];

        const addCondition = (r) => {
            if (!r.conditions) r.conditions = [];
            r.conditions.push({type:'DOMAIN',value:'',not:false,noResolve:false,src:''});
        };

        const addRule = (kind) => {
            if (!uiState.value.rules) uiState.value.rules = [];
            const matchIdx = uiState.value.rules.findIndex(r => r.type === 'MATCH' && !r.logic);
            let newRule;
            const fallbackTarget = (config.value['proxy-groups'] && config.value['proxy-groups'][0]) ? config.value['proxy-groups'][0].name : 'DIRECT';
            if (kind === 'AND' || kind === 'OR') {
                newRule = { logic: kind, not: false, target: fallbackTarget, conditions: [{ type: 'DOMAIN', value: '', not: false, noResolve: false, src: '' }] };
            } else {
                newRule = { type: 'GEOSITE', value: '', target: fallbackTarget, noResolve: false, not: false, src: '' };
            }
            if (matchIdx !== -1) uiState.value.rules.splice(matchIdx, 0, newRule);
            else uiState.value.rules.push(newRule);
            scrollToBottom();
        };

        const draggedRuleIndex = ref(null);
        const ruleDragOverIndex = ref(null);

        const onRuleDragStart = (idx, e) => {
            draggedRuleIndex.value = idx;
            ruleDragOverIndex.value = idx;
            if (e && e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                try {
                    e.dataTransfer.setData('text/plain', String(idx));
                } catch (err) {
                    console.warn('规则拖拽数据写入失败:', err);
                }
            }
        };

        const onRuleDragEnter = (idx) => {
            if (draggedRuleIndex.value === null) return;
            ruleDragOverIndex.value = idx;
        };

        const onRuleDragEnd = () => {
            draggedRuleIndex.value = null;
            ruleDragOverIndex.value = null;
        };

        const onRuleDrop = (idx) => {
            const from = draggedRuleIndex.value;
            if (from === null || !uiState.value.rules) {
                onRuleDragEnd();
                return;
            }

            const list = uiState.value.rules;
            const to = idx;
            if (from < 0 || to < 0 || from >= list.length || to >= list.length) {
                onRuleDragEnd();
                return;
            }

            const insertAt = from < to ? to - 1 : to;
            if (insertAt === from) {
                onRuleDragEnd();
                return;
            }

            const item = list.splice(from, 1)[0];
            if (item === undefined) {
                onRuleDragEnd();
                return;
            }

            list.splice(insertAt, 0, item);
            onRuleDragEnd();
        };

        return {
            formatConditions,
            addCondition,
            addRule,
            draggedRuleIndex,
            ruleDragOverIndex,
            onRuleDragStart,
            onRuleDragEnter,
            onRuleDrop,
            onRuleDragEnd,
            parseRuleString,
            RULE_TYPE_GROUPS,
            LOGIC_RULE_TYPE_GROUPS,
            IP_RULE_TYPES
        };
    };
})(window);
