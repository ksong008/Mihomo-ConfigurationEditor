(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createPersistenceModule = function (ctx) {
        const {
            watch,
            onMounted,
            config,
            uiState,
            providersList,
            ruleProvidersList,
            isLocating,
            renderStatus,
            getDefaultConfig,
            defaultConfigSnapshot,
            defaultUiStateSnapshot,
            parseSingleProxyNode,
            normalizeImportedConfigData,
            safeBuildYaml,
            injectRegionGroups,
            ensureGroupCollapseState,
            ensureRuleProviderCollapseState,
            sanitizeNftMarks,
            normalizeNftablesConfig,
            getSanitizedUiStateForSave,
            getListenPort,
            deepMerge,
            clearPersistedStorage,
            setCacheWarning,
            storageVersion,
            storageKey,
            storageBackupKey,
            restoreLegacyStorageKeys
        } = ctx;

        let suspendPersistence = false;

        const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);

        const safeJsonClone = (value, fallback = {}) => {
            try {
                return JSON.parse(JSON.stringify(value));
            } catch (err) {
                return fallback;
            }
        };

        const ensureArray = (value) => {
            if (Array.isArray(value)) return value;
            if (value === undefined || value === null || value === '' || value === false) return [];
            if (isPlainObject(value)) return Object.values(value);
            return [value];
        };

        const normalizeSnifferUiState = () => {
            const defaultSniff = { HTTP: '', TLS: '', QUIC: '' };
            const defaultOverrides = { HTTP: false, TLS: false, QUIC: false };

            if (!isPlainObject(uiState.value.snifferSniff)) {
                uiState.value.snifferSniff = { ...defaultSniff };
            } else {
                uiState.value.snifferSniff = {
                    HTTP: String(uiState.value.snifferSniff.HTTP || ''),
                    TLS: String(uiState.value.snifferSniff.TLS || ''),
                    QUIC: String(uiState.value.snifferSniff.QUIC || '')
                };
            }

            if (!isPlainObject(uiState.value.snifferSniffOverrideDestination)) {
                uiState.value.snifferSniffOverrideDestination = { ...defaultOverrides };
            } else {
                uiState.value.snifferSniffOverrideDestination = {
                    HTTP: !!uiState.value.snifferSniffOverrideDestination.HTTP,
                    TLS: !!uiState.value.snifferSniffOverrideDestination.TLS,
                    QUIC: !!uiState.value.snifferSniffOverrideDestination.QUIC
                };
            }
        };

        const unwrapPersistedPayload = (raw) => {
            if (!raw) return null;

            let parsed;
            try {
                parsed = JSON.parse(raw);
            } catch (err) {
                return null;
            }

            if (!isPlainObject(parsed)) return null;

            if (Number(parsed.version) === storageVersion && isPlainObject(parsed.data)) {
                return parsed.data;
            }

            if (
                parsed.config !== undefined
                || parsed.uiState !== undefined
                || parsed.providersList !== undefined
                || parsed.ruleProvidersList !== undefined
            ) {
                return parsed;
            }

            return null;
        };

        const capturePersistedState = () => ({
            config: safeJsonClone(config.value, {}),
            uiState: getSanitizedUiStateForSave(uiState.value, config.value),
            providersList: safeJsonClone(providersList.value, []),
            ruleProvidersList: safeJsonClone(ruleProvidersList.value, [])
        });

        const writePersistedState = ({ replaceBackup = false } = {}) => {
            const payload = {
                version: storageVersion,
                savedAt: new Date().toISOString(),
                data: capturePersistedState()
            };

            try {
                const serialized = JSON.stringify(payload);
                const previous = localStorage.getItem(storageKey);
                if (replaceBackup) {
                    localStorage.setItem(storageBackupKey, serialized);
                } else if (previous && previous !== serialized) {
                    localStorage.setItem(storageBackupKey, previous);
                }
                localStorage.setItem(storageKey, serialized);
            } catch (err) {
                console.warn('本地缓存写入失败，已跳过持久化:', err);
            }
        };

        const resetStateToDefaults = () => {
            config.value = safeJsonClone(defaultConfigSnapshot, getDefaultConfig());
            uiState.value = safeJsonClone(defaultUiStateSnapshot, {});
            providersList.value = [];
            ruleProvidersList.value = [];
        };

        let buildTimeout;
        watch([config, uiState, providersList, ruleProvidersList], () => {
            if (suspendPersistence) return;
            if (!isLocating.value) renderStatus.value = '实时渲染中...';

            clearTimeout(buildTimeout);
            buildTimeout = setTimeout(() => {
                const ok = safeBuildYaml('state watcher');
                if (!ok) return;

                writePersistedState();
            }, 150);
        }, { deep: true });

        const applyPersistedPayload = (payload) => {
            resetStateToDefaults();

            if (payload.config) {
                deepMerge(config.value, normalizeImportedConfigData(payload.config));
            }

            if (isPlainObject(payload.uiState)) {
                deepMerge(uiState.value, payload.uiState);
                normalizeSnifferUiState();

                if (!Object.prototype.hasOwnProperty.call(payload.uiState, 'tunDnsHijackEnabled')) {
                    uiState.value.tunDnsHijackEnabled = !!String(uiState.value.tunDnsHijack || '').trim();
                }
                if (!Object.prototype.hasOwnProperty.call(payload.uiState, 'enableDnsFallback')) {
                    uiState.value.enableDnsFallback = !!String(uiState.value.dnsFallback || '').trim();
                }
                if (!Object.prototype.hasOwnProperty.call(payload.uiState, 'enableNameserverPolicy')) {
                    uiState.value.enableNameserverPolicy = !!String(uiState.value.dnsNameserverPolicy || '').trim();
                    if (!uiState.value.enableNameserverPolicy && config.value && config.value.dns) {
                        config.value.dns['direct-nameserver-follow-policy'] = false;
                    }
                }
                if (!Object.prototype.hasOwnProperty.call(payload.uiState, 'enableProxyServerNameserverPolicy')) {
                    uiState.value.enableProxyServerNameserverPolicy = !!String(uiState.value.dnsProxyServerNameserverPolicy || '').trim();
                }
            }

            providersList.value = payload.providersList
                ? ensureArray(payload.providersList).filter(isPlainObject)
                : [];
            ruleProvidersList.value = payload.ruleProvidersList
                ? ensureArray(payload.ruleProvidersList).filter(isPlainObject)
                : [];
        };

        const finalizeHydratedState = () => {
            if (config.value.proxies && Array.isArray(config.value.proxies)) {
                config.value.proxies = config.value.proxies.map(px => parseSingleProxyNode(px)).filter(Boolean);
            }

            ensureGroupCollapseState();
            ensureRuleProviderCollapseState();
            normalizeSnifferUiState();

            uiState.value.nftablesConfig = normalizeNftablesConfig(uiState.value.nftablesConfig, config.value);
            sanitizeNftMarks();

            if (config.value && config.value.dns) {
                config.value.dns.listen = String(getListenPort(config.value.dns.listen, 53));
            }
        };

        const restorePersistedState = () => {
            const candidates = [storageKey, storageBackupKey, ...restoreLegacyStorageKeys];
            let sawPersistedState = false;
            let cacheIssueDetected = false;

            for (const key of candidates) {
                let raw = null;
                try {
                    raw = localStorage.getItem(key);
                } catch (err) {
                    console.warn('读取本地缓存失败，已跳过:', key, err);
                    continue;
                }

                if (!raw) continue;
                sawPersistedState = true;

                const payload = unwrapPersistedPayload(raw);
                if (!payload) {
                    console.warn('本地缓存格式无效，已跳过:', key);
                    cacheIssueDetected = true;
                    continue;
                }

                try {
                    applyPersistedPayload(payload);
                    finalizeHydratedState();

                    if (safeBuildYaml(`restore cache ${key}`)) {
                        if (key !== storageKey) {
                            writePersistedState({ replaceBackup: true });
                            cacheIssueDetected = true;
                        }
                        if (typeof setCacheWarning === 'function') {
                            setCacheWarning(cacheIssueDetected ? '检测到旧缓存或损坏缓存，已自动使用可恢复的数据继续加载。建议点击“清理缓存并重载”，避免后续再次出现页面异常。' : '');
                        }
                        return true;
                    }
                } catch (err) {
                    console.warn('本地缓存恢复失败，已跳过:', key, err);
                    cacheIssueDetected = true;
                }
            }

            resetStateToDefaults();
            injectRegionGroups();
            finalizeHydratedState();

            if (sawPersistedState) {
                console.warn('所有本地缓存均恢复失败，已回退到默认配置并清理缓存。');
                clearPersistedStorage();
                if (typeof setCacheWarning === 'function') {
                    setCacheWarning('检测到本地缓存异常，当前已回退默认配置。为避免再次白屏，建议点击“清理缓存并重载”。');
                }
            } else if (typeof setCacheWarning === 'function') {
                setCacheWarning('');
            }

            safeBuildYaml(sawPersistedState ? 'cache fallback to defaults' : 'initial mount');
            writePersistedState({ replaceBackup: sawPersistedState });
            return false;
        };

        onMounted(() => {
            suspendPersistence = true;
            try {
                restorePersistedState();
            } catch (e) {
                console.error('应用启动恢复失败，已回退默认配置:', e);
                resetStateToDefaults();
                injectRegionGroups();
                finalizeHydratedState();
                clearPersistedStorage();
                safeBuildYaml('startup fallback');
                writePersistedState({ replaceBackup: true });
            } finally {
                suspendPersistence = false;
            }
        });

        return {
            writePersistedState,
            resetStateToDefaults,
            restorePersistedState
        };
    };
})(window);
