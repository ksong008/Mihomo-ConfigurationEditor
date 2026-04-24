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
                try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
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

        const parseRuleString = (rStr) => {
            if (typeof rStr !== 'string') return null;
            let parts = splitByComma(rStr);

            if (['AND', 'OR'].includes(parts[0]) && parts.length === 3) {
                let logic = parts[0];
                let innerStr = parts[1].replace(/^\(+|\)+$/g, '');
                let target = parts[2];
                let condStrs = splitByComma(innerStr);
                let conditions = condStrs.map(c => {
                    let stripped = c.replace(/^\(+|\)+$/g, '');
                    let cParts = splitByComma(stripped);
                    let cNot = false;
                    if (cParts[0] === 'NOT') {
                        cNot = true;
                        cParts = splitByComma((cParts[1]||'').replace(/^\(+|\)+$/g, ''));
                    }
                    let val = (cParts[1]||'').replace(/^"|"$/g, '');
                    let src = '';
                    const srcIdx = cParts.findIndex(part => part === 'src');
                    if (srcIdx > -1 && cParts[srcIdx + 1] !== undefined) src = cParts[srcIdx + 1];
                    return { type: cParts[0], value: val, not: cNot, noResolve: cParts.includes('no-resolve'), src };
                });
                return { logic, not: false, target, conditions };
            }

            if (parts[0] === 'NOT' && parts.length === 3) {
                let innerStr = parts[1].replace(/^\(+|\)+$/g, '');
                let innerParts = splitByComma(innerStr);
                if (['AND', 'OR'].includes(innerParts[0])) {
                    let logicRule = parseRuleString(`${innerParts[0]},${innerParts[1]},${parts[2]}`);
                    if (logicRule) logicRule.not = true;
                    return logicRule;
                } else {
                    let cParts = innerParts;
                    let val = (cParts[1]||'').replace(/^"|"$/g, '');
                    let src = '';
                    const srcIdx = cParts.findIndex(part => part === 'src');
                    if (srcIdx > -1 && cParts[srcIdx + 1] !== undefined) src = cParts[srcIdx + 1];
                    return { type: cParts[0], value: val, target: parts[2], not: true, noResolve: cParts.includes('no-resolve'), src };
                }
            }

            if (parts[0] === 'MATCH') return { type: 'MATCH', value: '', target: parts[1] || 'DIRECT', noResolve: false, not: false, src: '' };

            let val = (parts[1]||'').replace(/^"|"$/g, '');
            let src = '';
            const srcIdx = parts.findIndex(part => part === 'src');
            if (srcIdx > -1 && parts[srcIdx + 1] !== undefined) src = parts[srcIdx + 1];
            return { type: parts[0], value: val, target: parts[2], noResolve: parts.includes('no-resolve'), not: false, src };
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
