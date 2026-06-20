(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createBootstrapUiModule = function (ctx) {
        const {
            ref,
            onMounted,
            nextTick,
            onErrorCaptured,
            storageKey,
            storageBackupKey,
            cleanupStorageKeys
        } = ctx;

        const crashError = ref(null);
        const cacheWarning = ref('');
        const bilingualLabelPattern = /^(.+?)\s*\(([^()]+)\)$/;
        const bilingualSkipTags = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'PRE', 'CODE', 'OPTION']);
        let bilingualLabelObserver = null;
        let bilingualLabelFrame = 0;

        const clearPersistedStorage = (includeLegacy = true) => {
            const keys = [storageKey, storageBackupKey];
            if (includeLegacy) keys.push(...cleanupStorageKeys);

            keys.forEach((key) => {
                try {
                    localStorage.removeItem(key);
                } catch (err) {
                    console.warn('清理本地缓存失败:', key, err);
                }
            });
        };

        onErrorCaptured((err, instance, info) => {
            console.error('UI渲染层捕获到异常，已自动拦截以防止白屏:', err, info);
            crashError.value = `Error: ${err.message}\nInfo: ${info}\nStack: ${err.stack}`;
            return false;
        });

        const forceClearCache = () => {
            clearPersistedStorage();
            location.reload();
        };

        const dismissCacheWarning = () => {
            cacheWarning.value = '';
        };

        const createDualLabelNode = (doc, zh, en) => {
            const wrapper = doc.createElement('span');
            wrapper.className = 'dual-label';

            const zhNode = doc.createElement('span');
            zhNode.className = 'dual-label-zh';
            zhNode.textContent = zh;

            const enNode = doc.createElement('span');
            enNode.className = 'dual-label-en';
            enNode.textContent = en;

            wrapper.appendChild(zhNode);
            wrapper.appendChild(enNode);
            return wrapper;
        };

        const shouldTransformBilingualText = (textNode) => {
            if (!textNode || !textNode.parentElement) return false;
            const parent = textNode.parentElement;
            if (bilingualSkipTags.has(parent.tagName)) return false;
            if (parent.closest('pre, code, textarea, option, .dual-label')) return false;

            const text = String(textNode.nodeValue || '');
            const normalized = text.replace(/\s+/g, ' ').trim();
            return bilingualLabelPattern.test(normalized);
        };

        const applyBilingualLabelLayout = (root = document.getElementById('app')) => {
            if (!root) return;

            const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
            const candidates = [];
            let current = walker.nextNode();

            while (current) {
                if (shouldTransformBilingualText(current)) candidates.push(current);
                current = walker.nextNode();
            }

            candidates.forEach((textNode) => {
                const rawText = String(textNode.nodeValue || '');
                const normalized = rawText.replace(/\s+/g, ' ').trim();
                const match = normalized.match(bilingualLabelPattern);
                if (!match || !textNode.parentNode) return;

                const [, zh, en] = match;
                const fragment = document.createDocumentFragment();
                if (/^\s+/.test(rawText)) fragment.appendChild(document.createTextNode(' '));
                fragment.appendChild(createDualLabelNode(document, zh.trim(), en.trim()));
                if (/\s+$/.test(rawText)) fragment.appendChild(document.createTextNode(' '));
                textNode.parentNode.insertBefore(fragment, textNode);
                textNode.parentNode.removeChild(textNode);
            });
        };

        const scheduleBilingualLabelLayout = () => {
            if (bilingualLabelFrame) window.cancelAnimationFrame(bilingualLabelFrame);
            bilingualLabelFrame = window.requestAnimationFrame(() => {
                bilingualLabelFrame = 0;
                applyBilingualLabelLayout();
            });
        };

        onMounted(() => {
            nextTick(() => {
                scheduleBilingualLabelLayout();
                const root = document.getElementById('app');
                if (!root) return;

                bilingualLabelObserver = new MutationObserver(() => {
                    scheduleBilingualLabelLayout();
                });
                bilingualLabelObserver.observe(root, {
                    subtree: true,
                    childList: true,
                    characterData: true
                });
            });
        });

        return {
            crashError,
            cacheWarning,
            clearPersistedStorage,
            forceClearCache,
            dismissCacheWarning
        };
    };
})(window);
