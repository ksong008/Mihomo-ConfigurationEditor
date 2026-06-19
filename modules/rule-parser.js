(function (window) {
    'use strict';

    if (!window.MihomoHelpers) {
        throw new Error('MihomoHelpers 未加载，请确认先引入 ./mihomo.helpers.js');
    }

    window.MihomoFeatureModules = window.MihomoFeatureModules || {};

    const { splitByComma } = window.MihomoHelpers;

    const formatConditions = (rule) => {
        if (!rule || !rule.conditions) return '';
        return rule.conditions.map((condition) => {
            if (!condition) return '';
            let result = '';
            if (condition.not) result += 'NOT ';
            result += condition.type || '';
            if (condition.value) result += `,${condition.value}`;
            if (condition.src) result += ` [src=${condition.src}]`;
            return result;
        }).join(rule.logic === 'AND' ? ' && ' : ' || ');
    };

    const isWrappedByParens = (text) => {
        const value = String(text || '').trim();
        if (!value.startsWith('(') || !value.endsWith(')')) return false;

        let depth = 0;
        let quote = '';
        let escaping = false;
        for (let index = 0; index < value.length; index += 1) {
            const char = value[index];
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
            if (char === '(') depth += 1;
            if (char === ')') depth -= 1;
            if (depth === 0 && index < value.length - 1) return false;
        }
        return depth === 0;
    };

    const stripWrappingParens = (text) => {
        let value = String(text || '').trim();
        while (isWrappedByParens(value)) {
            value = value.slice(1, -1).trim();
        }
        return value;
    };

    const stripQuotes = (value) => {
        const text = String(value || '').trim();
        if (text.length >= 2 && ((text[0] === '"' && text[text.length - 1] === '"') || (text[0] === "'" && text[text.length - 1] === "'"))) {
            return text.slice(1, -1);
        }
        return text;
    };

    const readBalancedGroup = (text, startIndex) => {
        let depth = 0;
        let quote = '';
        let escaping = false;
        for (let index = startIndex; index < text.length; index += 1) {
            const char = text[index];
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
            if (char === '(') depth += 1;
            if (char === ')') depth -= 1;
            if (depth === 0) {
                return { value: text.slice(startIndex, index + 1), endIndex: index + 1 };
            }
        }
        return { value: text.slice(startIndex), endIndex: text.length };
    };

    const splitLogicConditions = (text) => {
        const value = stripWrappingParens(text);
        const conditions = [];
        let index = 0;

        while (index < value.length) {
            while (value[index] === ',' || /\s/.test(value[index] || '')) index += 1;
            if (index >= value.length) break;

            let not = false;
            if (value.slice(index, index + 4) === 'NOT,') {
                not = true;
                index += 4;
            }

            let raw = '';
            if (value[index] === '(') {
                const group = readBalancedGroup(value, index);
                raw = group.value;
                index = group.endIndex;
            } else {
                const nextComma = value.indexOf(',', index);
                const end = nextComma === -1 ? value.length : nextComma;
                raw = value.slice(index, end);
                index = end;
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

        const srcIdx = parts.findIndex((part) => part === 'src');
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

    const parseRuleString = (ruleText) => {
        if (typeof ruleText !== 'string') return null;
        const parts = splitByComma(ruleText);

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

        if (parts[0] === 'MATCH') {
            return { type: 'MATCH', value: '', target: parts[1] || 'DIRECT', noResolve: false, not: false, src: '' };
        }

        const condition = parseCondition(ruleText);
        return { ...condition, target: parts[2] };
    };

    window.MihomoFeatureModules.RuleParser = Object.freeze({
        formatConditions,
        parseRuleString,
        parseCondition,
        parseLogicRule,
        splitLogicConditions
    });
})(window);
