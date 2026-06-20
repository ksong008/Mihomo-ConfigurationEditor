(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createRuleProviderEditor = function (ctx) {
        const {
            ref,
            watch,
            uiState,
            ruleProvidersList,
            scrollToBottom
        } = ctx;
        const providerModel = window.MihomoCore && window.MihomoCore.ProviderModel;
        if (!providerModel) {
            throw new Error('ProviderModel 未加载，请确认先引入 ./core/provider-model.js');
        }
        const {
            createRuleProviderState,
            getRuleProviderUrl: buildRuleProviderUrl
        } = providerModel;

        const setDragData = (e, value) => {
            if (!e || !e.dataTransfer) return;
            try {
                e.dataTransfer.setData('text/plain', String(value));
            } catch (err) {
                console.warn('拖拽数据写入失败:', err);
            }
        };

        const addRuleProvider = () => {
            ruleProvidersList.value.push(createRuleProviderState());
            scrollToBottom();
        };

        const removeRuleProvider = (idx) => ruleProvidersList.value.splice(idx, 1);

        const toggleRuleProviderCollapse = (rp) => {
            if (!rp) return;
            rp._collapsed = !rp._collapsed;
        };

        const collapseAllRuleProviders = () => {
            (ruleProvidersList.value || []).forEach((rp) => {
                if (rp) rp._collapsed = true;
            });
        };

        const expandAllRuleProviders = () => {
            (ruleProvidersList.value || []).forEach((rp) => {
                if (rp) rp._collapsed = false;
            });
        };

        const ensureRuleProviderCollapseState = () => {
            const list = ruleProvidersList.value;
            if (!Array.isArray(list)) return;

            list.forEach((rp) => {
                if (!rp || typeof rp !== 'object') return;
                if (typeof rp._collapsed !== 'boolean') {
                    rp._collapsed = false;
                }
            });
        };

        watch(
            [
                () => ruleProvidersList.value,
                () => (ruleProvidersList.value || []).length
            ],
            () => {
                ensureRuleProviderCollapseState();
            },
            { immediate: true, flush: 'sync' }
        );

        const ruleProviderDrag = ref({ fromIndex: -1, overIndex: -1 });

        const onRuleProviderDragStart = (idx, e) => {
            const list = ruleProvidersList.value || [];
            if (idx < 0 || idx >= list.length) return;

            ruleProviderDrag.value = { fromIndex: idx, overIndex: idx };

            if (e && e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                setDragData(e, idx);
            }
        };

        const onRuleProviderDragOver = (idx) => {
            if (ruleProviderDrag.value.fromIndex < 0) return;
            ruleProviderDrag.value.overIndex = idx;
        };

        const onRuleProviderDrop = (idx) => {
            const list = ruleProvidersList.value;
            if (!Array.isArray(list)) return;

            const from = ruleProviderDrag.value.fromIndex;
            const to = idx;

            if (from < 0 || to < 0 || from === to || from >= list.length || to >= list.length) {
                onRuleProviderDragEnd();
                return;
            }

            const insertAt = from < to ? to - 1 : to;
            if (insertAt === from) {
                onRuleProviderDragEnd();
                return;
            }

            const moved = list.splice(from, 1)[0];
            if (moved === undefined) {
                onRuleProviderDragEnd();
                return;
            }

            list.splice(insertAt, 0, moved);
            onRuleProviderDragEnd();
        };

        const onRuleProviderDragEnd = () => {
            ruleProviderDrag.value = { fromIndex: -1, overIndex: -1 };
        };

        const hasDuplicateRuleProviderName = (name, currentItem = null) => {
            const target = String(name || '').trim();
            if (!target) return false;

            return (ruleProvidersList.value || []).some((item) => {
                if (!item || item === currentItem) return false;
                return String(item.name || '').trim() === target;
            });
        };

        const updateRuleProviderName = (rp, newName, e = null) => {
            if (!rp || typeof rp !== 'object') return;

            const oldName = String(rp.name || '');
            const nextName = String(newName ?? '');
            const trimmedNext = nextName.trim();

            if (trimmedNext && hasDuplicateRuleProviderName(trimmedNext, rp)) {
                window.alert(`规则集名称重复：${trimmedNext}`);
                if (e && e.target) e.target.value = oldName;
                return;
            }

            rp.name = nextName;
            if (oldName && oldName !== nextName) {
                (uiState.value.rules || []).forEach((r) => {
                    if (r.type === 'RULE-SET' && r.value === oldName) r.value = nextName;
                    if (r.logic && r.conditions) {
                        r.conditions.forEach((cond) => {
                            if (cond.type === 'RULE-SET' && cond.value === oldName) cond.value = nextName;
                        });
                    }
                });
            }
        };

        const getRuleProviderUrl = (rp) => {
            return buildRuleProviderUrl(rp, {
                useMirrorForRuleProviders: uiState.value.useMirrorForRuleProviders
            });
        };

        return {
            addRuleProvider,
            removeRuleProvider,
            toggleRuleProviderCollapse,
            collapseAllRuleProviders,
            expandAllRuleProviders,
            ensureRuleProviderCollapseState,
            onRuleProviderDragStart,
            onRuleProviderDragOver,
            onRuleProviderDrop,
            onRuleProviderDragEnd,
            ruleProviderDrag,
            updateRuleProviderName,
            getRuleProviderUrl
        };
    };
})(window);
