(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createProviderGroupEditor = function (ctx) {
        const {
            ref,
            watch,
            config,
            providersList,
            scrollToBottom
        } = ctx;
        const providerGroupModel = window.MihomoCore && window.MihomoCore.ProviderGroupModel;
        if (!providerGroupModel) {
            throw new Error('ProviderGroupModel 未加载，请确认先引入 ./core/provider-group-model.js');
        }
        const {
            getAvailableGroupMembers: buildAvailableGroupMembers,
            getAvailableEmptyFallbackMembers: buildAvailableEmptyFallbackMembers,
            getOrderedAvailableGroupMembers: buildOrderedAvailableGroupMembers,
            getOrderedGroupUseProviders: buildOrderedGroupUseProviders,
            pruneInvalidGroupProxyMembers: pruneInvalidGroupProxyMembersState,
            pruneInvalidGroupUseMembers: pruneInvalidGroupUseMembersState,
            groupIncludesAllProxies,
            groupIncludesAllProviders
        } = providerGroupModel;

        const createProxyGroupState = (overrides = {}) => ({
            name: '',
            type: 'select',
            proxies: [],
            use: [],
            filter: '',
            'exclude-filter': '',
            'exclude-type': '',
            url: 'https://www.gstatic.com/generate_204',
            interval: 300,
            tolerance: 50,
            timeout: 0,
            lazy: false,
            'max-failed-times': 5,
            'disable-udp': false,
            'interface-name': '',
            'routing-mark': '',
            strategy: 'consistent-hashing',
            'include-all': false,
            'include-all-proxies': false,
            'include-all-providers': false,
            'expected-status': '',
            'empty-fallback': '',
            hidden: false,
            icon: '',
            _collapsed: false,
            ...overrides
        });

        const setDragData = (e, value) => {
            if (!e || !e.dataTransfer) return;
            try {
                e.dataTransfer.setData('text/plain', String(value));
            } catch (err) {
                console.warn('拖拽数据写入失败:', err);
            }
        };

        const addGroup = () => {
            config.value['proxy-groups'].push(createProxyGroupState({
                name: `Group-${(config.value['proxy-groups'] || []).length + 1}`
            }));
            scrollToBottom();
        };

        const removeGroup = (idx) => {
            config.value['proxy-groups'].splice(idx, 1);
        };

        const toggleGroupCollapse = (g) => {
            if (!g) return;
            g._collapsed = !g._collapsed;
        };

        const collapseAllGroups = () => {
            (config.value['proxy-groups'] || []).forEach((g) => {
                if (g) g._collapsed = true;
            });
        };

        const expandAllGroups = () => {
            (config.value['proxy-groups'] || []).forEach((g) => {
                if (g) g._collapsed = false;
            });
        };

        const ensureGroupCollapseState = (forceCollapse = false) => {
            const groups = config.value['proxy-groups'];
            if (!Array.isArray(groups)) return;

            groups.forEach((g) => {
                if (!g || typeof g !== 'object') return;
                if (forceCollapse) {
                    g._collapsed = true;
                } else if (typeof g._collapsed !== 'boolean') {
                    g._collapsed = true;
                }
            });
        };

        watch(
            [
                () => config.value['proxy-groups'],
                () => (config.value['proxy-groups'] || []).length
            ],
            () => {
                ensureGroupCollapseState(false);
            },
            { immediate: true, flush: 'sync' }
        );

        const removeGroupProxyMember = (g, idx) => {
            if (!g || !Array.isArray(g.proxies)) return;
            g.proxies.splice(idx, 1);
        };

        const pruneInvalidGroupProxyMembers = () => {
            pruneInvalidGroupProxyMembersState({
                proxies: config.value.proxies,
                groups: config.value['proxy-groups']
            });
        };

        watch(
            [
                () => config.value.proxies,
                () => config.value['proxy-groups'],
                () => (config.value.proxies || []).length,
                () => (config.value['proxy-groups'] || []).length
            ],
            () => {
                pruneInvalidGroupProxyMembers();
            },
            { immediate: true, flush: 'sync' }
        );

        const getAvailableGroupMembers = (currentGroupName) => {
            return buildAvailableGroupMembers({
                proxies: config.value.proxies,
                groups: config.value['proxy-groups'],
                currentGroupName
            });
        };

        const getAvailableEmptyFallbackMembers = () => {
            return buildAvailableEmptyFallbackMembers(config.value.proxies);
        };

        const getOrderedAvailableGroupMembers = (g) => {
            return buildOrderedAvailableGroupMembers({
                group: g,
                proxies: config.value.proxies,
                groups: config.value['proxy-groups']
            });
        };

        const groupProxyDrag = ref({ groupName: '', fromIndex: -1 });

        const onInlineGroupMemberDragStart = (g, name, e) => {
            if (!g || groupIncludesAllProxies(g) || !Array.isArray(g.proxies)) return;
            const idx = g.proxies.indexOf(name);
            if (idx < 0) return;

            if (e && e.currentTarget && e.currentTarget.classList) {
                e.currentTarget.classList.add('dragging');
            }

            onGroupProxyDragStart(g, idx, e);
        };

        const onInlineGroupMemberDragOver = (g, name, e) => {
            if (!g || groupIncludesAllProxies(g) || !Array.isArray(g.proxies)) return;
            if (!g.proxies.includes(name)) return;

            if (e && e.dataTransfer) {
                e.dataTransfer.dropEffect = 'move';
            }
        };

        const onInlineGroupMemberDrop = (g, name, e) => {
            if (!g || groupIncludesAllProxies(g) || !Array.isArray(g.proxies)) {
                onGroupProxyDragEnd();
                return;
            }

            const idx = g.proxies.indexOf(name);
            if (idx < 0) {
                onGroupProxyDragEnd();
                return;
            }

            onGroupProxyDrop(g, idx);

            if (e && e.currentTarget && e.currentTarget.classList) {
                e.currentTarget.classList.remove('dragging');
            }
        };

        const onGroupProxyDragStart = (g, idx, e) => {
            if (!g || !Array.isArray(g.proxies)) return;
            groupProxyDrag.value = { groupName: g.name, fromIndex: idx };
            if (e && e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                setDragData(e, idx);
            }
        };

        const onGroupProxyDrop = (g, idx) => {
            if (!g || !Array.isArray(g.proxies)) return;
            const drag = groupProxyDrag.value;
            if (!drag || drag.groupName !== g.name) return;

            const from = drag.fromIndex;
            const to = idx;
            if (from < 0 || to < 0 || from === to) {
                onGroupProxyDragEnd();
                return;
            }

            const moved = g.proxies.splice(from, 1)[0];
            if (moved === undefined) {
                onGroupProxyDragEnd();
                return;
            }

            g.proxies.splice(to, 0, moved);
            onGroupProxyDragEnd();
        };

        const onGroupProxyDragEnd = () => {
            groupProxyDrag.value = { groupName: '', fromIndex: -1 };
            document.querySelectorAll('[data-group-member-draggable="1"].dragging').forEach((el) => el.classList.remove('dragging'));
        };

        const groupUseDrag = ref({ groupName: '', fromIndex: -1 });

        const onGroupUseDragStart = (g, name, e) => {
            if (!g || groupIncludesAllProviders(g) || !Array.isArray(g.use)) return;
            const idx = g.use.indexOf(name);
            if (idx < 0) return;

            groupUseDrag.value = { groupName: g.name, fromIndex: idx };

            if (e && e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                setDragData(e, idx);
            }
        };

        const onGroupUseDragOver = (g, name, e) => {
            if (!g || groupIncludesAllProviders(g) || !Array.isArray(g.use)) return;
            if (!g.use.includes(name)) return;

            if (e && e.dataTransfer) {
                e.dataTransfer.dropEffect = 'move';
            }
        };

        const onGroupUseDrop = (g, name) => {
            if (!g || groupIncludesAllProviders(g) || !Array.isArray(g.use)) {
                onGroupUseDragEnd();
                return;
            }

            const drag = groupUseDrag.value;
            if (!drag || drag.groupName !== g.name) return;

            const from = drag.fromIndex;
            const to = g.use.indexOf(name);

            if (from < 0 || to < 0 || from === to) {
                onGroupUseDragEnd();
                return;
            }

            const moved = g.use.splice(from, 1)[0];
            if (moved === undefined) {
                onGroupUseDragEnd();
                return;
            }

            g.use.splice(to, 0, moved);
            onGroupUseDragEnd();
        };

        const onGroupUseDragEnd = () => {
            groupUseDrag.value = { groupName: '', fromIndex: -1 };
            document.querySelectorAll('[data-group-use-draggable="1"].dragging').forEach((el) => el.classList.remove('dragging'));
        };

        const proxyGroupDrag = ref({ fromIndex: -1, overIndex: -1 });

        const onProxyGroupDragStart = (idx, e) => {
            const groups = config.value['proxy-groups'] || [];
            if (idx < 0 || idx >= groups.length) return;

            proxyGroupDrag.value = { fromIndex: idx, overIndex: idx };

            if (e && e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                setDragData(e, idx);
            }
        };

        const onProxyGroupDragOver = (idx) => {
            if (proxyGroupDrag.value.fromIndex < 0) return;
            proxyGroupDrag.value.overIndex = idx;
        };

        const onProxyGroupDrop = (idx) => {
            const groups = config.value['proxy-groups'];
            if (!Array.isArray(groups)) return;

            const from = proxyGroupDrag.value.fromIndex;
            const to = idx;

            if (from < 0 || to < 0 || from === to || from >= groups.length || to >= groups.length) {
                onProxyGroupDragEnd();
                return;
            }

            const insertAt = from < to ? to - 1 : to;
            if (insertAt === from) {
                onProxyGroupDragEnd();
                return;
            }

            const moved = groups.splice(from, 1)[0];
            if (moved === undefined) {
                onProxyGroupDragEnd();
                return;
            }

            groups.splice(insertAt, 0, moved);
            onProxyGroupDragEnd();
        };

        const onProxyGroupDragEnd = () => {
            proxyGroupDrag.value = { fromIndex: -1, overIndex: -1 };
        };

        const getOrderedGroupUseProviders = (g) => {
            return buildOrderedGroupUseProviders({
                group: g,
                providers: providersList.value
            });
        };

        const pruneInvalidGroupUseMembers = () => {
            pruneInvalidGroupUseMembersState({
                groups: config.value['proxy-groups'],
                providers: providersList.value
            });
        };

        watch(
            [
                () => providersList.value,
                () => config.value['proxy-groups'],
                () => (providersList.value || []).length,
                () => (config.value['proxy-groups'] || []).length
            ],
            () => {
                pruneInvalidGroupUseMembers();
            },
            { immediate: true, flush: 'sync' }
        );

        const autoCategorizeProxies = () => {
            if (!config.value['proxy-groups'] || !config.value.proxies) return;
            config.value['proxy-groups'].forEach((g) => {
                if (!g.filter || g.filter.trim() === '') return;

                try {
                    let jsPattern = g.filter;
                    let flags = '';
                    if (jsPattern.startsWith('(?i)')) {
                        jsPattern = jsPattern.substring(4);
                        flags = 'i';
                    }
                    const regex = new RegExp(jsPattern, flags);

                    const matched = config.value.proxies
                        .filter((px) => regex.test(px.name))
                        .map((px) => px.name);

                    matched.forEach((name) => {
                        if (!g.proxies) g.proxies = [];
                        if (!g.proxies.includes(name)) g.proxies.push(name);
                    });

                    (providersList.value || []).forEach((prov) => {
                        if (!g.use) g.use = [];
                        if (prov.name && !g.use.includes(prov.name)) g.use.push(prov.name);
                    });
                } catch (err) {
                    console.warn('节点分组过滤表达式无效，已跳过:', g.filter, err);
                }
            });
        };

        const injectRegionGroups = () => {
            if (!config.value['proxy-groups']) config.value['proxy-groups'] = [];
            const regions = [
                { name: '香港节点', filter: '(?i)港|hk|hongkong|hong kong' },
                { name: '台湾节点', filter: '(?i)台|tw|taiwan' },
                { name: '韩国节点', filter: '(?i)韩|kr|korea|south korea' },
                { name: '日本节点', filter: '(?i)日|jp|japan' },
                { name: '新加坡节点', filter: '(?i)新|sg|singapore' },
                { name: '美国节点', filter: '(?i)美|us|united states|america' },
                { name: '其他国家', filter: '(?i)^(?!.*(?:港|hk|台|tw|韩|kr|日|jp|新|sg|美|us)).*$' }
            ];

            let mainGroup = config.value['proxy-groups'].find((g) => g.name === 'Proxy');
            if (!mainGroup) {
                mainGroup = createProxyGroupState({
                    name: 'Proxy',
                    proxies: ['自动选择', 'DIRECT']
                });
                config.value['proxy-groups'].unshift(mainGroup);
            }
            let autoGroup = config.value['proxy-groups'].find((g) => g.name === '自动选择');
            if (!autoGroup) {
                autoGroup = createProxyGroupState({
                    name: '自动选择',
                    type: 'url-test',
                    use: (providersList.value || []).map((p) => p.name),
                    lazy: true
                });
                config.value['proxy-groups'].splice(1, 0, autoGroup);
            }

            regions.forEach((region) => {
                if (!config.value['proxy-groups'].find((g) => g.name === region.name)) {
                    config.value['proxy-groups'].push(createProxyGroupState({
                        name: region.name,
                        type: 'url-test',
                        use: (providersList.value || []).map((p) => p.name),
                        filter: region.filter,
                        lazy: true
                    }));
                }
                if (!mainGroup.proxies.includes(region.name)) mainGroup.proxies.push(region.name);
            });

            autoCategorizeProxies();
        };

        return {
            createProxyGroupState,
            addGroup,
            removeGroup,
            toggleGroupCollapse,
            collapseAllGroups,
            expandAllGroups,
            ensureGroupCollapseState,
            removeGroupProxyMember,
            pruneInvalidGroupProxyMembers,
            getAvailableGroupMembers,
            getAvailableEmptyFallbackMembers,
            getOrderedAvailableGroupMembers,
            groupIncludesAllProxies,
            groupIncludesAllProviders,
            onInlineGroupMemberDragStart,
            onInlineGroupMemberDragOver,
            onInlineGroupMemberDrop,
            onGroupProxyDragStart,
            onGroupProxyDrop,
            onGroupProxyDragEnd,
            groupProxyDrag,
            getOrderedGroupUseProviders,
            onGroupUseDragStart,
            onGroupUseDragOver,
            onGroupUseDrop,
            onGroupUseDragEnd,
            groupUseDrag,
            onProxyGroupDragStart,
            onProxyGroupDragOver,
            onProxyGroupDrop,
            onProxyGroupDragEnd,
            proxyGroupDrag,
            pruneInvalidGroupUseMembers,
            injectRegionGroups,
            autoCategorizeProxies
        };
    };
})(window);
