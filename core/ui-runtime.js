(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createUiRuntimeModule = function (ctx) {
        const { ref, watch, nextTick, fullYaml } = ctx;

        const currentTab = ref('general');
        const yamlPreviewBox = ref(null);
        const renderStatus = ref('实时渲染');
        const isLocating = ref(false);
        let scrollTimeout = null;
        let lastTarget = '';

        const handleFocus = (e) => {
            const el = e.target.closest('[data-yaml-target]');
            if (el) {
                const keyword = el.getAttribute('data-yaml-target');
                if (keyword && keyword !== lastTarget) {
                    lastTarget = keyword;
                    locateAndScroll(keyword);
                }
            }
        };

        const locateAndScroll = (keyword) => {
            if (!yamlPreviewBox.value) return;
            clearTimeout(scrollTimeout);
            isLocating.value = true;
            renderStatus.value = `追踪: ${keyword.trim().slice(0, 15)}...`;

            scrollTimeout = setTimeout(() => {
                const container = yamlPreviewBox.value;
                const lines = fullYaml.value.split('\n');
                const idx = lines.findIndex(l => l.includes(keyword));
                if (idx !== -1) {
                    const pre = container.querySelector('pre');
                    if (pre) {
                        const scrollHeight = pre.getBoundingClientRect().height;
                        const lineHeight = lines.length > 0 ? (scrollHeight / lines.length) : 0;
                        const targetY = Math.max(0, idx * lineHeight - 60);
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
