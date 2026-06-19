(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createProvidersModule = function (ctx) {
        const {
            ref,
            watch,
            config,
            uiState,
            providersList,
            ruleProvidersList,
            scrollToBottom,
            parseSingleProxyNode,
            sanitizeProxyNodeForYaml,
            sanitizeProxyByCapabilities,
            getProxyNetworkOptions,
            proxySupportsTransport,
            proxySupportsToggle,
            proxyHasTlsSection,
            proxySupportsTlsClientFingerprint,
            getProxyValidationIssues,
            getProxyTlsMode,
            askConfirm
        } = ctx;
        const providerModel = window.MihomoCore && window.MihomoCore.ProviderModel;
        if (!providerModel) {
            throw new Error('ProviderModel 未加载，请确认先引入 ./core/provider-model.js');
        }
        const providerGroupModel = window.MihomoCore && window.MihomoCore.ProviderGroupModel;
        if (!providerGroupModel) {
            throw new Error('ProviderGroupModel 未加载，请确认先引入 ./core/provider-group-model.js');
        }
        const providerFallbackModel = window.MihomoCore && window.MihomoCore.ProviderFallbackModel;
        if (!providerFallbackModel) {
            throw new Error('ProviderFallbackModel 未加载，请确认先引入 ./core/provider-fallback-model.js');
        }
        const providerRenameModel = window.MihomoCore && window.MihomoCore.ProviderRenameModel;
        if (!providerRenameModel) {
            throw new Error('ProviderRenameModel 未加载，请确认先引入 ./core/provider-rename-model.js');
        }
        const {
            cloneJsonValue,
            createProviderState,
            createRuleProviderState,
            getRuleProviderUrl: buildRuleProviderUrl
        } = providerModel;
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
        const {
            normalizeProviderFallbackPayloadState: normalizeProviderFallbackPayload,
            getInlinePayloadPreview: buildInlinePayloadPreview,
            getProviderFallbackSnapshotNames,
            getProviderFallbackDetachedNames: buildProviderFallbackDetachedNames,
            removeProviderFallbackPayloadNode,
            getProviderFallbackPayloadPreview: buildProviderFallbackPayloadPreview
        } = providerFallbackModel;
        const { createProviderRenameTracker } = providerRenameModel;
        const renameTracker = createProviderRenameTracker();
        const scrollProviderCardIntoView = (selector) => {
            window.requestAnimationFrame(() => {
                window.requestAnimationFrame(() => {
                    const scrollBox = document.getElementById('main-scroll');
                    const target = document.querySelector(selector);
                    if (!scrollBox || !target) return;

                    const stickyHeader = target.closest('.bg-white.p-5.rounded-xl')?.querySelector('.sticky.top-0');
                    const headerOffset = stickyHeader ? stickyHeader.getBoundingClientRect().height : 72;
                    const containerRect = scrollBox.getBoundingClientRect();
                    const targetRect = target.getBoundingClientRect();
                    const absoluteTop = targetRect.top - containerRect.top + scrollBox.scrollTop;
                    const safeTop = Math.max(0, absoluteTop - headerOffset - 12);

                    scrollBox.scrollTo({ top: safeTop, behavior: 'smooth' });
                });
            });
        };
        const setDragData = (e, value) => {
            if (!e || !e.dataTransfer) return;
            try {
                e.dataTransfer.setData('text/plain', String(value));
            } catch (err) {
                console.warn('拖拽数据写入失败:', err);
            }
        };
        const normalizeChainProvidersState = () => {
            const sourceProviders = (providersList.value || []).filter((p) => p && !p._chainMode);
            (providersList.value || []).forEach((p) => {
                if (!p || p._chainMode !== 'provider') return;
                const source = sourceProviders.find((item) => item.name === p._sourceProviderName && ['http', 'file'].includes(item.type));
                if (!source) return;
                p.type = source.type;
                p.url = source.url;
                p.path = source.path;
                p.interval = source.interval;
                p.proxy = source.proxy;
                p.sizeLimit = source.sizeLimit;
                p.ageSecretKey = source.ageSecretKey;
                p.headers = source.headers;
                p.lazy = source.lazy;
                p.healthCheckEnable = source.healthCheckEnable;
                p.healthUrl = source.healthUrl;
                p.healthCheckInterval = source.healthCheckInterval;
                p.healthCheckLazy = source.healthCheckLazy;
                p.healthCheckTimeout = source.healthCheckTimeout;
                p.healthExpectedStatus = source.healthExpectedStatus;
            });
        };
        const normalizeProviderFallbackPayloadState = () => {
            normalizeProviderFallbackPayload({
                providers: providersList.value,
                proxies: config.value.proxies,
                cloneJsonValue,
                sanitizeProxyNodeForYaml
            });
        };
        const normalizeProxyTransportState = () => {
            (config.value.proxies || []).forEach((px) => {
                if (!px || typeof px !== 'object') return;
                if (typeof sanitizeProxyByCapabilities === 'function') {
                    sanitizeProxyByCapabilities(px);
                    return;
                }
                const options = getProxyNetworkOptions(px.type);
                const allowed = new Set(options.map((item) => item.value));
                if (allowed.size === 0) {
                    px.network = 'tcp';
                } else if (!allowed.has(px.network)) {
                    px.network = options[0].value;
                }
                const tlsMode = getProxyTlsMode(px.type);
                if (tlsMode === 'required') {
                    px.tls = true;
                } else if (!proxySupportsToggle(px.type, 'tls')) {
                    px.tls = false;
                }
                if (!proxySupportsToggle(px.type, 'reality')) {
                    px.reality = false;
                }
                if (!proxySupportsToggle(px.type, 'smux') || (proxySupportsTransport(px.type) && px.network !== 'tcp')) {
                    if (px.smux && typeof px.smux === 'object') {
                        px.smux.enabled = false;
                    }
                }
                if (px.type !== 'trojan' && px['ss-opts']) {
                    px['ss-opts'].enabled = false;
                }
                if (tlsMode === 'none' && !proxySupportsToggle(px.type, 'reality')) {
                    px.reality = false;
                    px.tls = false;
                }
            });
        };

        const addManualProxy = () => {
            config.value.proxies.push(parseSingleProxyNode({ type: 'vless' }));
            scrollToBottom();
        };

        watch(
            () => providersList.value,
            () => {
                normalizeChainProvidersState();
                normalizeProviderFallbackPayloadState();
            },
            { immediate: true, deep: true, flush: 'sync' }
        );

        watch(
            () => config.value.proxies,
            () => {
                normalizeProxyTransportState();
                normalizeProviderFallbackPayloadState();
            },
            { immediate: true, deep: true, flush: 'sync' }
        );

        const addGroup = () => {
            config.value['proxy-groups'].push({
                name: `Group-${(config.value['proxy-groups'] || []).length + 1}`,
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
                _collapsed: false
            });
            scrollToBottom();
        };

        const removeGroup = (idx) => {
            config.value['proxy-groups'].splice(idx, 1);
        };

        const groupProxyDrag = ref({ groupName: '', fromIndex: -1 });

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

            let mainGroup = config.value['proxy-groups'].find(g => g.name === 'Proxy');
            if (!mainGroup) {
                mainGroup = {
                    name: 'Proxy',
                    type: 'select',
                    proxies: ['自动选择', 'DIRECT'],
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
                    hidden: false,
                    icon: ''
                };
                config.value['proxy-groups'].unshift(mainGroup);
            }
            let autoGroup = config.value['proxy-groups'].find(g => g.name === '自动选择');
            if (!autoGroup) {
                autoGroup = {
                    name: '自动选择',
                    type: 'url-test',
                    proxies: [],
                    use: (providersList.value || []).map(p => p.name),
                    filter: '',
                    'exclude-filter': '',
                    'exclude-type': '',
                    url: 'https://www.gstatic.com/generate_204',
                    interval: 300,
                    tolerance: 50,
                    timeout: 0,
                    lazy: true,
                    'max-failed-times': 5,
                    'disable-udp': false,
                    'interface-name': '',
                    'routing-mark': '',
                    strategy: 'consistent-hashing',
                    'include-all': false,
                    'include-all-proxies': false,
                    'include-all-providers': false,
                    'expected-status': '',
                    hidden: false,
                    icon: ''
                };
                config.value['proxy-groups'].splice(1, 0, autoGroup);
            }

            regions.forEach(r => {
                if (!config.value['proxy-groups'].find(g => g.name === r.name)) {
                    config.value['proxy-groups'].push({
                        name: r.name,
                        type: 'url-test',
                        proxies: [],
                        use: (providersList.value || []).map(p => p.name),
                        filter: r.filter,
                        'exclude-filter': '',
                        'exclude-type': '',
                        url: 'https://www.gstatic.com/generate_204',
                        interval: 300,
                        tolerance: 50,
                        timeout: 0,
                        lazy: true,
                        'max-failed-times': 5,
                        'disable-udp': false,
                        'interface-name': '',
                        'routing-mark': '',
                        strategy: 'consistent-hashing',
                        'include-all': false,
                        'include-all-proxies': false,
                        'include-all-providers': false,
                        'expected-status': '',
                        hidden: false,
                        icon: ''
                    });
                }
                if (!mainGroup.proxies.includes(r.name)) mainGroup.proxies.push(r.name);
            });

            autoCategorizeProxies();
        };

        const autoCategorizeProxies = () => {
            if (!config.value['proxy-groups'] || !config.value.proxies) return;
            config.value['proxy-groups'].forEach(g => {
                if (g.filter && g.filter.trim() !== '') {
                    try {
                        let jsPattern = g.filter;
                        let flags = '';
                        if (jsPattern.startsWith('(?i)')) {
                            jsPattern = jsPattern.substring(4);
                            flags = 'i';
                        }
                        const regex = new RegExp(jsPattern, flags);

                        const matched = config.value.proxies
                            .filter(px => regex.test(px.name))
                            .map(px => px.name);

                        matched.forEach(name => {
                            if (!g.proxies) g.proxies = [];
                            if (!g.proxies.includes(name)) g.proxies.push(name);
                        });

                        (providersList.value || []).forEach(prov => {
                            if (!g.use) g.use = [];
                            if (prov.name && !g.use.includes(prov.name)) g.use.push(prov.name);
                        });
                    } catch (e) {
                        console.warn('节点分组过滤表达式无效，已跳过:', g.filter, e);
                    }
                }
            });
        };

        const pickPanel = (p) => {
            uiState.value.selectedPanel = p.id;
            config.value['external-ui-url'] = uiState.value.useMirrorForPanels ? p.mirrorUrl : p.rawUrl;
        };

        const addProvider = () => {
            const nextName = `Provider-${(providersList.value || []).length + 1}`;
            providersList.value.push(createProviderState({ name: nextName }));
            scrollProviderCardIntoView(`[data-provider-kind="subscription"][data-provider-name="${CSS.escape(nextName)}"]`);
        };
        const addInlineChainProvider = () => {
            const nextName = `Chain-${(providersList.value || []).length + 1}`;
            providersList.value.push(createProviderState({
                name: nextName,
                type: 'inline',
                _chainMode: 'inline',
                _sourceProviderName: ''
            }));
            window.requestAnimationFrame(() => {
                const detail = document.getElementById('inline-chain-details');
                if (detail && detail.tagName === 'DETAILS') detail.open = true;
                scrollProviderCardIntoView(`[data-provider-kind="inline-chain"][data-provider-name="${CSS.escape(nextName)}"]`);
            });
        };
        const addSourceChainProvider = () => {
            const nextName = `Provider-Chain-${(providersList.value || []).length + 1}`;
            providersList.value.push(createProviderState({
                name: nextName,
                type: 'http',
                _chainMode: 'provider',
                _sourceProviderName: ''
            }));
            window.requestAnimationFrame(() => {
                const detail = document.getElementById('inline-chain-details');
                if (detail && detail.tagName === 'DETAILS') detail.open = true;
                scrollProviderCardIntoView(`[data-provider-kind="inline-chain"][data-provider-name="${CSS.escape(nextName)}"]`);
            });
        };
        const getSubscriptionProviders = () => (providersList.value || []).filter((p) => p && !p._chainMode);
        const getInlineChainProviders = () => (providersList.value || []).filter((p) => p && p._chainMode === 'inline');
        const getProviderChainProviders = () => (providersList.value || []).filter((p) => p && p._chainMode === 'provider');
        const getChainProviders = () => (providersList.value || []).filter((p) => p && p._chainMode);
        const getChainSourceProviders = () => getSubscriptionProviders().filter((p) => ['http', 'file'].includes(p.type));

        const removeProvider = (idx) => providersList.value.splice(idx, 1);

        const addRuleProvider = () => {
            ruleProvidersList.value.push(createRuleProviderState());
            scrollToBottom();
        };

        const removeRuleProvider = (idx) => ruleProvidersList.value.splice(idx, 1);

        const ruleProviderDrag = ref({ fromIndex: -1, overIndex: -1 });

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
                (uiState.value.rules || []).forEach(r => {
                    if (r.type === 'RULE-SET' && r.value === oldName) r.value = nextName;
                    if (r.logic && r.conditions) {
                        r.conditions.forEach(cond => {
                            if (cond.type === 'RULE-SET' && cond.value === oldName) cond.value = nextName;
                        });
                    }
                });
            }
        };

        const ensureRenameSnapshots = () => {
            renameTracker.ensureSnapshots({
                providers: providersList.value,
                proxies: config.value.proxies,
                groups: config.value['proxy-groups']
            });
        };

        watch(
            [
                () => providersList.value,
                () => config.value.proxies,
                () => config.value['proxy-groups'],
                () => (providersList.value || []).length,
                () => (config.value.proxies || []).length,
                () => (config.value['proxy-groups'] || []).length
            ],
            () => {
                ensureRenameSnapshots();
            },
            { immediate: true, flush: 'sync' }
        );

        const updateProviderName = (p, newName) => {
            renameTracker.updateProviderName({
                provider: p,
                newName,
                providers: providersList.value,
                groups: config.value['proxy-groups']
            });
        };

        const updateProxyName = (px, newName) => {
            renameTracker.updateProxyName({
                proxy: px,
                newName,
                providers: providersList.value,
                ruleProviders: ruleProvidersList.value,
                proxies: config.value.proxies,
                groups: config.value['proxy-groups'],
                rules: uiState.value.rules
            });
        };

        const updateGroupName = (g, newName) => {
            renameTracker.updateGroupName({
                group: g,
                newName,
                providers: providersList.value,
                ruleProviders: ruleProvidersList.value,
                proxies: config.value.proxies,
                groups: config.value['proxy-groups'],
                rules: uiState.value.rules
            });
        };

        const getRuleProviderUrl = (rp) => {
            return buildRuleProviderUrl(rp, {
                useMirrorForRuleProviders: uiState.value.useMirrorForRuleProviders
            });
        };

        const clearLists = () => {
            if (askConfirm('确定要清空所有的节点、订阅和规则列表吗？')) {
                config.value.proxies = [];
                config.value['proxy-groups'] = [];
                providersList.value = [];
                ruleProvidersList.value = [];
                uiState.value.rules = [];
            }
        };

        const getInlinePayloadPreview = (inlineProxies) => {
            return buildInlinePayloadPreview({
                inlineProxies,
                proxies: config.value.proxies,
                sanitizeProxyNodeForYaml,
                dumpYaml: jsyaml.dump
            });
        };
        const getProviderFallbackDetachedNames = (provider) => {
            return buildProviderFallbackDetachedNames({
                provider,
                proxies: config.value.proxies
            });
        };
        const getProviderFallbackPayloadPreview = (provider) => {
            return buildProviderFallbackPayloadPreview({
                provider,
                proxies: config.value.proxies,
                cloneJsonValue,
                sanitizeProxyNodeForYaml,
                dumpYaml: jsyaml.dump
            });
        };

        return {
            pickPanel,
            addManualProxy,
            addGroup,
            removeGroup,
            toggleGroupCollapse,
            collapseAllGroups,
            expandAllGroups,
            ensureGroupCollapseState,
            removeGroupProxyMember,
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
            pruneInvalidGroupProxyMembers,
            pruneInvalidGroupUseMembers,
            injectRegionGroups,
            autoCategorizeProxies,
            addProvider,
            addInlineChainProvider,
            addSourceChainProvider,
            getSubscriptionProviders,
            getInlineChainProviders,
            getProviderChainProviders,
            getChainProviders,
            getChainSourceProviders,
            removeProvider,
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
            updateProviderName,
            updateProxyName,
            updateGroupName,
            getRuleProviderUrl,
            clearLists,
            getInlinePayloadPreview,
            getProviderFallbackSnapshotNames,
            getProviderFallbackDetachedNames,
            removeProviderFallbackPayloadNode,
            getProviderFallbackPayloadPreview,
            getProxyNetworkOptions,
            proxySupportsTransport,
            proxySupportsToggle,
            proxyHasTlsSection,
            proxySupportsTlsClientFingerprint,
            getProxyValidationIssues
        };
    };
})(window);
