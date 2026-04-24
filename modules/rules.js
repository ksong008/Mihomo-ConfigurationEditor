(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createRulesModule = function (ctx) {
        const { ref, config, uiState, scrollToBottom } = ctx;
        const { splitByComma } = window.MihomoHelpers;
        const IP_RULE_TYPES = ['GEOIP', 'SRC-GEOIP', 'IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'IP-SUFFIX', 'IP-ASN', 'SRC-IP-SUFFIX', 'SRC-IP-ASN'];

        const formatConditions = (r) => {
            if (!r || !r.conditions) return '';
            return r.conditions.map(c => {
                if(!c) return '';
                let res = '';
                if (c.not) res += 'NOT ';
                res += c.type || '';
                if (c.value) res += ',' + c.value;
                if (c.src) res += ` [src=${c.src}]`;
                return res;
            }).join(r.logic === 'AND' ? ' && ' : ' || ');
        };

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

        const isWrappedByParens = (text) => {
            const s = String(text || '').trim();
            if (!s.startsWith('(') || !s.endsWith(')')) return false;

            let depth = 0;
            let quote = '';
            let escaping = false;
            for (let i = 0; i < s.length; i++) {
                const char = s[i];
                if (quote) {
                    if (escaping) escaping = false;
                    else if (char === '\\') escaping = true;
                    else if (char === quote) quote = '';
                    continue;
                }
                if (char === '"' || char === "'") {
                    quote = char;
                    continue;
                }
                if (char === '(') depth++;
                if (char === ')') depth--;
                if (depth === 0 && i < s.length - 1) return false;
            }
            return depth === 0;
        };

        const stripWrappingParens = (text) => {
            let s = String(text || '').trim();
            while (isWrappedByParens(s)) {
                s = s.slice(1, -1).trim();
            }
            return s;
        };

        const stripQuotes = (value) => {
            const s = String(value || '').trim();
            if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) {
                return s.slice(1, -1);
            }
            return s;
        };

        const readBalancedGroup = (text, startIndex) => {
            let depth = 0;
            let quote = '';
            let escaping = false;
            for (let i = startIndex; i < text.length; i++) {
                const char = text[i];
                if (quote) {
                    if (escaping) escaping = false;
                    else if (char === '\\') escaping = true;
                    else if (char === quote) quote = '';
                    continue;
                }
                if (char === '"' || char === "'") {
                    quote = char;
                    continue;
                }
                if (char === '(') depth++;
                if (char === ')') depth--;
                if (depth === 0) {
                    return { value: text.slice(startIndex, i + 1), endIndex: i + 1 };
                }
            }
            return { value: text.slice(startIndex), endIndex: text.length };
        };

        const splitLogicConditions = (text) => {
            const s = stripWrappingParens(text);
            const conditions = [];
            let i = 0;

            while (i < s.length) {
                while (s[i] === ',' || /\s/.test(s[i] || '')) i++;
                if (i >= s.length) break;

                let not = false;
                if (s.slice(i, i + 4) === 'NOT,') {
                    not = true;
                    i += 4;
                }

                let raw = '';
                if (s[i] === '(') {
                    const group = readBalancedGroup(s, i);
                    raw = group.value;
                    i = group.endIndex;
                } else {
                    const nextComma = s.indexOf(',', i);
                    const end = nextComma === -1 ? s.length : nextComma;
                    raw = s.slice(i, end);
                    i = end;
                }

                const normalized = stripWrappingParens(raw);
                if (normalized) conditions.push({ raw: normalized, not });
            }

            return conditions;
        };

        const parseCondition = (raw, forcedNot = false) => {
            let text = stripWrappingParens(raw);
            let not = forcedNot;
            let parts = splitByComma(text);

            if (parts[0] === 'NOT') {
                not = true;
                text = stripWrappingParens(parts[1] || '');
                parts = splitByComma(text);
            }

            const srcIdx = parts.findIndex(part => part === 'src');
            return {
                type: parts[0] || 'DOMAIN',
                value: stripQuotes(parts[1] || ''),
                not,
                noResolve: parts.includes('no-resolve'),
                src: srcIdx > -1 && parts[srcIdx + 1] !== undefined ? parts[srcIdx + 1] : ''
            };
        };

        const parseLogicRule = (logic, conditionText, target, not = false) => {
            const conditions = splitLogicConditions(conditionText)
                .map((item) => parseCondition(item.raw, item.not))
                .filter((condition) => condition.type);
            return { logic, not, target, conditions };
        };

        const parseRuleString = (rStr) => {
            if (typeof rStr !== 'string') return null;
            let parts = splitByComma(rStr);

            if (['AND', 'OR'].includes(parts[0]) && parts.length >= 3) {
                return parseLogicRule(parts[0], parts[1], parts[2]);
            }

            if (parts[0] === 'NOT' && parts.length >= 3) {
                const innerText = stripWrappingParens(parts[1]);
                const innerParts = splitByComma(innerText);
                if (['AND', 'OR'].includes(innerParts[0])) {
                    return parseLogicRule(innerParts[0], innerParts[1], parts[2], true);
                }

                const condition = parseCondition(innerText, true);
                return { ...condition, target: parts[2] };
            }

            if (parts[0] === 'MATCH') return { type: 'MATCH', value: '', target: parts[1] || 'DIRECT', noResolve: false, not: false, src: '' };

            const condition = parseCondition(rStr);
            return { ...condition, target: parts[2] };
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
            IP_RULE_TYPES
        };
    };
})(window);
