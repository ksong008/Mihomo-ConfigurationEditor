(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};
    window.MihomoFeatureModules.createRulesModule = function (ctx) {
        const { ref, config, uiState, scrollToBottom } = ctx;
        const { splitByComma } = window.MihomoHelpers;

        const formatConditions = (r) => {
            if (!r || !r.conditions) return '';
            return r.conditions.map(c => {
                if(!c) return '';
                let res = '';
                if (c.not) res += 'NOT ';
                res += c.type || '';
                if (c.value) res += ',' + c.value;
                return res;
            }).join(r.logic === 'AND' ? ' && ' : ' || ');
        };

        const addCondition = (r) => {
            if (!r.conditions) r.conditions = [];
            r.conditions.push({type:'DOMAIN',value:'',not:false,noResolve:false});
        };

        const addRule = (kind) => {
            if (!uiState.value.rules) uiState.value.rules = [];
            const matchIdx = uiState.value.rules.findIndex(r => r.type === 'MATCH' && !r.logic);
            let newRule;
            const fallbackTarget = (config.value['proxy-groups'] && config.value['proxy-groups'][0]) ? config.value['proxy-groups'][0].name : 'DIRECT';
            if (kind === 'AND' || kind === 'OR') {
                newRule = { logic: kind, not: false, target: fallbackTarget, conditions: [{ type: 'DOMAIN', value: '', not: false, noResolve: false }] };
            } else {
                newRule = { type: 'GEOSITE', value: '', target: fallbackTarget, noResolve: false, not: false };
            }
            if (matchIdx !== -1) uiState.value.rules.splice(matchIdx, 0, newRule);
            else uiState.value.rules.push(newRule);
            scrollToBottom();
        };

        const draggedRuleIndex = ref(null);
        const onRuleDragStart = (idx, e) => { draggedRuleIndex.value = idx; e.dataTransfer.effectAllowed = 'move'; };
        const onRuleDragEnter = () => {}; const onRuleDragEnd = () => { draggedRuleIndex.value = null; (uiState.value.rules||[]).forEach(r => r.draggable = false); };
        const onRuleDrop = (idx) => { const from = draggedRuleIndex.value; if (from !== null && from !== idx && uiState.value.rules) { const item = uiState.value.rules.splice(from, 1)[0]; uiState.value.rules.splice(idx, 0, item); } onRuleDragEnd(); };

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
                    return { type: cParts[0], value: val, not: cNot, noResolve: cParts.includes('no-resolve') };
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
                    return { type: cParts[0], value: val, target: parts[2], not: true, noResolve: cParts.includes('no-resolve') };
                }
            }

            if (parts[0] === 'MATCH') return { type: 'MATCH', value: '', target: parts[1] || 'DIRECT', noResolve: false, not: false };

            let val = (parts[1]||'').replace(/^"|"$/g, '');
            return { type: parts[0], value: val, target: parts[2], noResolve: parts.includes('no-resolve'), not: false };
        };

        return {
            formatConditions,
            addCondition,
            addRule,
            draggedRuleIndex,
            onRuleDragStart,
            onRuleDragEnter,
            onRuleDrop,
            onRuleDragEnd,
            parseRuleString
        };
    };
})(window);
