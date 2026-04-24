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
            askConfirm
        } = ctx;
        const proxyNetworkOptionsMap = {
            vless: [
                { value: 'tcp', label: 'TCP' },
                { value: 'ws', label: 'WebSocket' },
                { value: 'grpc', label: 'gRPC' },
                { value: 'h2', label: 'HTTP/2 (h2)' },
                { value: 'http', label: 'HTTP' },
                { value: 'xhttp', label: 'xHTTP' }
            ],
            vmess: [
                { value: 'tcp', label: 'TCP' },
                { value: 'ws', label: 'WebSocket' },
                { value: 'grpc', label: 'gRPC' },
                { value: 'h2', label: 'HTTP/2 (h2)' },
                { value: 'http', label: 'HTTP' }
            ],
            trojan: [
                { value: 'tcp', label: 'TCP' },
                { value: 'ws', label: 'WebSocket' },
                { value: 'grpc', label: 'gRPC' }
            ],
            masque: [
                { value: 'quic', label: 'QUIC' },
                { value: 'h2', label: 'HTTP/2 (h2)' }
            ]
        };
        const proxyToggleSupport = {
            udp: new Set(['vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'socks5', 'snell']),
            tfo: new Set(['vless', 'vmess', 'trojan', 'ss', 'ssr', 'http', 'socks5', 'snell', 'ssh', 'anytls']),
            mptcp: new Set(['vless', 'vmess', 'trojan', 'ss', 'http', 'socks5', 'anytls']),
            tls: new Set(['vless', 'vmess', 'trojan', 'ss', 'http', 'socks5', 'sudoku']),
            reality: new Set(['vless', 'trojan']),
            smux: new Set(['vless', 'vmess', 'trojan', 'ss', 'http', 'socks5', 'sudoku'])
        };
        const implicitTlsTypes = new Set(['hysteria2', 'hysteria', 'tuic', 'masque', 'anytls']);
        const getProxyNetworkOptions = (type) => proxyNetworkOptionsMap[type] || [];
        const proxySupportsTransport = (type) => getProxyNetworkOptions(type).length > 0;
        const proxySupportsToggle = (type, toggle) => !!proxyToggleSupport[toggle] && proxyToggleSupport[toggle].has(type);
        const normalizeProxyTransportState = () => {
            (config.value.proxies || []).forEach((px) => {
                if (!px || typeof px !== 'object') return;
                const options = getProxyNetworkOptions(px.type);
                const allowed = new Set(options.map((item) => item.value));
                if (allowed.size === 0) {
                    px.network = 'tcp';
                } else if (!allowed.has(px.network)) {
                    px.network = 'tcp';
                }
                if (!proxySupportsToggle(px.type, 'tls')) {
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
                if (!proxySupportsToggle(px.type, 'tls') && !proxySupportsToggle(px.type, 'reality') && !implicitTlsTypes.has(px.type)) {
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
            () => config.value.proxies,
            () => {
                normalizeProxyTransportState();
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
                'dialer-proxy': '',
                strategy: 'consistent-hashing',
                'include-all-proxies': false,
                'include-all-providers': false,
                'expected-status': '',
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

        const getValidStaticGroupMemberNames = (currentGroupName = '') => {
            const names = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE']);

            (config.value.proxies || []).forEach((p) => {
                const name = String(p?.name || '').trim();
                if (name) names.add(name);
            });

            (config.value['proxy-groups'] || []).forEach((group) => {
                const name = String(group?.name || '').trim();
                if (name && name !== currentGroupName) names.add(name);
            });

            return names;
        };

        const pruneInvalidGroupProxyMembers = () => {
            const groups = config.value['proxy-groups'];
            if (!Array.isArray(groups)) return;

            groups.forEach((g) => {
                if (!Array.isArray(g.proxies)) {
                    g.proxies = [];
                    return;
                }

                const validNames = getValidStaticGroupMemberNames(g.name);
                const next = g.proxies.filter((name) => validNames.has(String(name || '').trim()));

                if (next.length !== g.proxies.length) {
                    g.proxies = next;
                }
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
            let groups = (config.value['proxy-groups'] || []).map(g => g.name);
            if (currentGroupName) groups = groups.filter(n => n !== currentGroupName);
            return ['DIRECT', 'REJECT', ...groups, ...(config.value.proxies || []).map(p => p.name)];
        };

        const getOrderedAvailableGroupMembers = (g) => {
            const available = getAvailableGroupMembers(g && g.name);
            if (!g || !Array.isArray(g.proxies) || g.proxies.length === 0) return available;

            const availableMap = new Map(available.map((name) => [String(name || '').trim(), name]));
            const selected = [];
            const selectedSet = new Set();

            g.proxies.forEach((name) => {
                const key = String(name || '').trim();
                if (!key || selectedSet.has(key) || !availableMap.has(key)) return;
                selectedSet.add(key);
                selected.push(availableMap.get(key));
            });

            const rest = available.filter((name) => !selectedSet.has(String(name || '').trim()));
            return [...selected, ...rest];
        };

        const onInlineGroupMemberDragStart = (g, name, e) => {
            if (!g || g['include-all-proxies'] || !Array.isArray(g.proxies)) return;
            const idx = g.proxies.indexOf(name);
            if (idx < 0) return;

            if (e && e.currentTarget && e.currentTarget.classList) {
                e.currentTarget.classList.add('dragging');
            }

            onGroupProxyDragStart(g, idx, e);
        };

        const onInlineGroupMemberDragOver = (g, name, e) => {
            if (!g || g['include-all-proxies'] || !Array.isArray(g.proxies)) return;
            if (!g.proxies.includes(name)) return;

            if (e && e.dataTransfer) {
                e.dataTransfer.dropEffect = 'move';
            }
        };

        const onInlineGroupMemberDrop = (g, name, e) => {
            if (!g || g['include-all-proxies'] || !Array.isArray(g.proxies)) {
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
                try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
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
            if (!g || g['include-all-providers'] || !Array.isArray(g.use)) return;
            const idx = g.use.indexOf(name);
            if (idx < 0) return;

            groupUseDrag.value = { groupName: g.name, fromIndex: idx };

            if (e && e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
            }
        };

        const onGroupUseDragOver = (g, name, e) => {
            if (!g || g['include-all-providers'] || !Array.isArray(g.use)) return;
            if (!g.use.includes(name)) return;

            if (e && e.dataTransfer) {
                e.dataTransfer.dropEffect = 'move';
            }
        };

        const onGroupUseDrop = (g, name) => {
            if (!g || g['include-all-providers'] || !Array.isArray(g.use)) {
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
                try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
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
            const available = (providersList.value || []).map((p) => p && p.name).filter(Boolean);
            if (!g || !Array.isArray(g.use) || g.use.length === 0) return available;

            const availableMap = new Map(available.map((name) => [String(name || '').trim(), name]));
            const selected = [];
            const selectedSet = new Set();

            g.use.forEach((name) => {
                const key = String(name || '').trim();
                if (!key || selectedSet.has(key) || !availableMap.has(key)) return;
                selectedSet.add(key);
                selected.push(availableMap.get(key));
            });

            const rest = available.filter((name) => !selectedSet.has(String(name || '').trim()));
            return [...selected, ...rest];
        };

        const pruneInvalidGroupUseMembers = () => {
            const groups = config.value['proxy-groups'];
            if (!Array.isArray(groups)) return;

            const validProviders = new Set(
                (providersList.value || [])
                    .map((p) => String((p && p.name) || '').trim())
                    .filter(Boolean)
            );

            groups.forEach((g) => {
                if (!Array.isArray(g.use)) {
                    g.use = [];
                    return;
                }

                const next = g.use.filter((name) => validProviders.has(String(name || '').trim()));
                if (next.length !== g.use.length) {
                    g.use = next;
                }
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
                    'dialer-proxy': '',
                    strategy: 'consistent-hashing',
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
                    'dialer-proxy': '',
                    strategy: 'consistent-hashing',
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
                        'dialer-proxy': '',
                        strategy: 'consistent-hashing',
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
                    } catch (e) {}
                }
            });
        };

        const pickPanel = (p) => {
            uiState.value.selectedPanel = p.id;
            config.value['external-ui-url'] = uiState.value.useMirrorForPanels ? p.mirrorUrl : p.rawUrl;
        };

        const addProvider = () => {
            providersList.value.push({
                name: `Provider-${(providersList.value || []).length + 1}`,
                type: 'http',
                url: '',
                path: '',
                interval: 3600,
                proxy: '',
                sizeLimit: '',
                headers: '',
                filter: '',
                excludeFilter: '',
                excludeType: '',
                healthCheckEnable: true,
                healthUrl: 'https://www.gstatic.com/generate_204',
                healthCheckInterval: 600,
                overrideDialerProxy: '',
                overrideAdditionalPrefix: '',
                overrideAdditionalSuffix: '',
                overrideProxyName: '',
                inlineProxies: [],
                lazy: true,
                healthCheckLazy: true,
                healthCheckTimeout: 5000,
                healthExpectedStatus: ''
            });
            scrollToBottom();
        };

        const removeProvider = (idx) => providersList.value.splice(idx, 1);

        const addRuleProvider = () => {
            ruleProvidersList.value.push({
                name: '',
                type: 'http',
                file: '',
                behavior: 'domain',
                format: 'mrs',
                interval: 86400,
                autoUrl: true,
                customUrl: '',
                path: '',
                proxy: '',
                sizeLimit: '',
                headers: '',
                payload: '',
                _collapsed: false
            });
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
                try { e.dataTransfer.setData('text/plain', String(idx)); } catch (err) {}
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

        const providerNameSnapshots = new WeakMap();
        const proxyNameSnapshots = new WeakMap();
        const groupNameSnapshots = new WeakMap();

        const ensureRenameSnapshots = () => {
            (providersList.value || []).forEach((p) => {
                if (p && typeof p === 'object' && !providerNameSnapshots.has(p)) {
                    providerNameSnapshots.set(p, String(p.name || ''));
                }
            });

            (config.value.proxies || []).forEach((px) => {
                if (px && typeof px === 'object' && !proxyNameSnapshots.has(px)) {
                    proxyNameSnapshots.set(px, String(px.name || ''));
                }
            });

            (config.value['proxy-groups'] || []).forEach((g) => {
                if (g && typeof g === 'object' && !groupNameSnapshots.has(g)) {
                    groupNameSnapshots.set(g, String(g.name || ''));
                }
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

        const replaceNameInList = (list, oldName, newName) => {
            if (!Array.isArray(list) || oldName === newName) return;
            for (let i = 0; i < list.length; i++) {
                if (list[i] === oldName) list[i] = newName;
            }
        };

        const replaceDialerProxyName = (target, oldName, newName, key = 'dialer-proxy') => {
            if (!target || typeof target !== 'object' || oldName === newName) return;
            if (target[key] === oldName) target[key] = newName;
        };

        const replaceProviderDialerRefs = (oldName, newName) => {
            (providersList.value || []).forEach((p) => {
                if (!p || typeof p !== 'object') return;
                if (p.proxy === oldName) p.proxy = newName;
                if (p.overrideDialerProxy === oldName) p.overrideDialerProxy = newName;
            });
        };

        const replaceRuleProviderProxyRefs = (oldName, newName) => {
            (ruleProvidersList.value || []).forEach((rp) => {
                if (!rp || typeof rp !== 'object') return;
                if (rp.proxy === oldName) rp.proxy = newName;
            });
        };

        const replaceProviderInlineProxyRefs = (oldName, newName) => {
            (providersList.value || []).forEach((p) => {
                if (!p || typeof p !== 'object') return;
                replaceNameInList(p.inlineProxies, oldName, newName);
            });
        };

        const replaceRuleTargets = (oldName, newName) => {
            (uiState.value.rules || []).forEach((r) => {
                if (r && r.target === oldName) r.target = newName;
            });
        };

        const updateProviderName = (p, newName) => {
            if (!p || typeof p !== 'object') return;
            const oldName = providerNameSnapshots.has(p) ? providerNameSnapshots.get(p) : String(p.name || '');
            p.name = newName;

            if (oldName === newName) return;

            (config.value['proxy-groups'] || []).forEach((g) => {
                replaceNameInList(g.use, oldName, newName);
            });

            providerNameSnapshots.set(p, String(newName || ''));
        };

        const updateProxyName = (px, newName) => {
            if (!px || typeof px !== 'object') return;
            const oldName = proxyNameSnapshots.has(px) ? proxyNameSnapshots.get(px) : String(px.name || '');
            px.name = newName;

            if (oldName === newName) return;

            (config.value['proxy-groups'] || []).forEach((g) => {
                replaceNameInList(g.proxies, oldName, newName);
                replaceDialerProxyName(g, oldName, newName);
            });

            replaceProviderDialerRefs(oldName, newName);
            replaceRuleProviderProxyRefs(oldName, newName);
            replaceProviderInlineProxyRefs(oldName, newName);

            (config.value.proxies || []).forEach((item) => {
                if (item !== px) replaceDialerProxyName(item, oldName, newName);
            });

            replaceRuleTargets(oldName, newName);
            proxyNameSnapshots.set(px, String(newName || ''));
        };

        const updateGroupName = (g, newName) => {
            if (!g || typeof g !== 'object') return;
            const oldName = groupNameSnapshots.has(g) ? groupNameSnapshots.get(g) : String(g.name || '');
            g.name = newName;

            if (oldName === newName) return;

            (config.value['proxy-groups'] || []).forEach((item) => {
                replaceNameInList(item.proxies, oldName, newName);
                replaceDialerProxyName(item, oldName, newName);
            });

            replaceProviderDialerRefs(oldName, newName);
            replaceRuleProviderProxyRefs(oldName, newName);

            (config.value.proxies || []).forEach((px) => {
                replaceDialerProxyName(px, oldName, newName);
            });

            replaceRuleTargets(oldName, newName);

            if (Array.isArray(g.proxies)) {
                g.proxies = g.proxies.filter((name) => String(name || '').trim() !== String(g.name || '').trim());
            }
            if (g['dialer-proxy'] === g.name) {
                g['dialer-proxy'] = '';
            }

            groupNameSnapshots.set(g, String(newName || ''));
        };

        const getRuleProviderUrl = (rp) => {
            if (!rp.autoUrl) return rp.customUrl;
            const targetName = rp.file ? rp.file.trim() : '';
            if (!targetName) return '';
            const base = uiState.value.useMirrorForRuleProviders
                ? 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo'
                : 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo';
            const folder = rp.behavior === 'ipcidr' ? 'geoip' : 'geosite';
            const ext = rp.format === 'text' ? 'list' : rp.format;
            return `${base}/${folder}/${targetName}.${ext}`;
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
            if (!inlineProxies || inlineProxies.length === 0) return '[]';
            const nodes = inlineProxies.map(name => {
                const px = (config.value.proxies || []).find(x => x.name === name);
                if (!px) return null;
                const cleanPx = JSON.parse(JSON.stringify(parseSingleProxyNode(px)));
                return cleanPx;
            }).filter(Boolean);
            try {
                return jsyaml.dump(nodes, { indent: 2, lineWidth: -1, sortKeys: false });
            } catch (e) {
                return '# Preview Error';
            }
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
            getOrderedAvailableGroupMembers,
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
            getProxyNetworkOptions,
            proxySupportsTransport,
            proxySupportsToggle
        };
    };
})(window);
