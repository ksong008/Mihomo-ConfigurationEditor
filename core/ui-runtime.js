(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createUiRuntimeModule = function (ctx) {
        const { ref, watch, nextTick } = ctx;

        const currentTab = ref('general');
        const yamlPreviewBox = ref(null);
        const renderStatus = ref('实时渲染');
        const isLocating = ref(false);
        let scrollTimeout = null;
        let lastTarget = '';
        const YAML_SPAN_ORDER = ['yaml-general', 'yaml-experimental', 'yaml-network', 'yaml-proxies', 'yaml-providers', 'yaml-rule-providers', 'yaml-groups', 'yaml-sub-rules', 'yaml-rules'];
        const TAB_SPAN_MAP = {
            general: ['yaml-general', 'yaml-experimental'],
            network: ['yaml-network'],
            providers: ['yaml-proxies', 'yaml-providers'],
            'rule-providers': ['yaml-rule-providers'],
            groups: ['yaml-groups'],
            rules: ['yaml-sub-rules', 'yaml-rules'],
            tproxy: ['yaml-general', 'yaml-network']
        };

        const normalizeKeyword = (keyword) => String(keyword || '').trim();
        const parseScopedKeyword = (keyword) => {
            const normalized = normalizeKeyword(keyword);
            if (!normalized.includes('@@')) return { scope: '', target: normalized };
            const [scope, target] = normalized.split('@@');
            return {
                scope: normalizeKeyword(scope),
                target: normalizeKeyword(target)
            };
        };
        const getSpanText = (spanId) => {
            const el = document.getElementById(spanId);
            return el ? String(el.textContent || '') : '';
        };
        const getAllLinesBeforeSpan = (spanId) => {
            let total = 0;
            for (const id of YAML_SPAN_ORDER) {
                if (id === spanId) break;
                total += getSpanText(id).split('\n').length - 1;
            }
            return total;
        };
        const scoreLineMatch = (line, keyword) => {
            const trimmedLine = String(line || '').trim();
            if (!trimmedLine || !keyword) return -1;
            if (trimmedLine === keyword) return 100;
            if (trimmedLine.startsWith(keyword)) return 80;
            if (trimmedLine.includes(keyword)) return 60;
            return -1;
        };
        const findLineIndexInSpan = (spanId, keyword) => {
            const text = getSpanText(spanId);
            if (!text) return -1;
            const lines = text.split('\n');
            let bestIndex = -1;
            let bestScore = -1;
            lines.forEach((line, index) => {
                const score = scoreLineMatch(line, keyword);
                if (score > bestScore) {
                    bestScore = score;
                    bestIndex = index;
                }
            });
            return bestIndex;
        };
        const findScopedLineIndexInSpan = (spanId, scope, target) => {
            const text = getSpanText(spanId);
            if (!text) return -1;
            const lines = text.split('\n');
            let scopeIndex = -1;
            let scopeScore = -1;

            lines.forEach((line, index) => {
                const score = scoreLineMatch(line, scope);
                if (score > scopeScore) {
                    scopeScore = score;
                    scopeIndex = index;
                }
            });

            if (scopeIndex === -1) return -1;
            if (!target) return scopeIndex;

            let bestIndex = -1;
            let bestScore = -1;
            for (let i = scopeIndex; i < lines.length; i++) {
                if (i > scopeIndex && lines[i].trim().startsWith('- name:')) break;
                const score = scoreLineMatch(lines[i], target);
                if (score > bestScore) {
                    bestScore = score;
                    bestIndex = i;
                }
            }

            return bestIndex !== -1 ? bestIndex : scopeIndex;
        };
        const findBestGlobalLineIndex = (keyword, preferredSpanIds = []) => {
            const scoped = parseScopedKeyword(keyword);
            const visited = new Set();
            const spanSearchOrder = [...preferredSpanIds, ...YAML_SPAN_ORDER];
            for (const spanId of spanSearchOrder) {
                if (visited.has(spanId)) continue;
                visited.add(spanId);
                const localIndex = scoped.scope
                    ? findScopedLineIndexInSpan(spanId, scoped.scope, scoped.target)
                    : findLineIndexInSpan(spanId, scoped.target);
                if (localIndex !== -1) return getAllLinesBeforeSpan(spanId) + localIndex;
            }
            if (scoped.scope) {
                return findBestGlobalLineIndex(scoped.target, preferredSpanIds);
            }
            return -1;
        };

        const handleFocus = (e) => {
            const el = e.target.closest('[data-yaml-target]');
            if (el) {
                const keyword = el.getAttribute('data-yaml-target');
                if (keyword && keyword !== lastTarget) {
                    lastTarget = keyword;
                    locateAndScroll(keyword, currentTab.value);
                }
            }
        };

        const locateAndScroll = (keyword, tabId = currentTab.value) => {
            if (!yamlPreviewBox.value) return;
            clearTimeout(scrollTimeout);
            const normalizedKeyword = normalizeKeyword(keyword);
            if (!normalizedKeyword) return;
            isLocating.value = true;
            renderStatus.value = `追踪: ${normalizedKeyword.slice(0, 20)}...`;

            scrollTimeout = setTimeout(() => {
                const container = yamlPreviewBox.value;
                const fullText = YAML_SPAN_ORDER.map((id) => getSpanText(id)).join('');
                const lines = fullText.split('\n');
                const idx = findBestGlobalLineIndex(normalizedKeyword, TAB_SPAN_MAP[tabId] || []);
                if (idx !== -1) {
                    const pre = container.querySelector('pre');
                    if (pre) {
                        const scrollHeight = pre.getBoundingClientRect().height;
                        const lineHeight = lines.length > 0 ? (scrollHeight / lines.length) : 0;
                        const targetY = Math.max(0, idx * lineHeight - (container.clientHeight / 2) + (lineHeight / 2));
                        container.scrollTo({ top: targetY, behavior: 'smooth' });
                    }
                }
                setTimeout(() => {
                    isLocating.value = false;
                    renderStatus.value = '实时渲染';
                }, 1000);
            }, 100);
        };

        watch(currentTab, (newTab) => {
            if (!yamlPreviewBox.value) return;
            lastTarget = '';
            nextTick(() => {
                setTimeout(() => {
                    const el = document.getElementById('yaml-' + newTab);
                    if (el) {
                        const container = yamlPreviewBox.value;
                        const pre = container.querySelector('pre');
                        if (!pre) return;
                        const topPos = el.offsetTop - pre.offsetTop;
                        container.scrollTo({ top: Math.max(0, topPos - 15), behavior: 'smooth' });
                    }
                }, 50);
            });
        });

        const scrollToBottom = () => {
            nextTick(() => {
                const scrollBox = document.getElementById('main-scroll');
                if (scrollBox) {
                    scrollBox.scrollTo({ top: scrollBox.scrollHeight, behavior: 'smooth' });
                }
            });
        };

        return {
            currentTab,
            yamlPreviewBox,
            renderStatus,
            isLocating,
            handleFocus,
            locateAndScroll,
            scrollToBottom
        };
    };
})(window);
