(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.createListenerEditor = function (ctx) {
        const {
            onMounted,
            config,
            uiState,
            parseYamlObjectText,
            parseYamlSequenceText,
            formatYamlSequenceText,
            getSuggestedListenerPort,
            normalizeTunnelListenerNetwork,
            tunnelListenerNetworkOptions,
            getShadowsocksCipherOptions,
            isSupportedShadowsocksCipher,
            isShadowsocks2022Cipher,
            generateShadowsocksPassword
        } = ctx;

        const addListener = () => {
            config.value.listeners.push({
                name: `listener-${config.value.listeners.length + 1}`,
                type: 'mixed',
                port: getSuggestedListenerPort(config.value, uiState.value, 7895),
                listen: '::',
                udp: true,
                cipher: '',
                password: '',
                network: ['tcp'],
                target: '',
                rule: '',
                proxy: '',
                token: '',
                certificate: '',
                'private-key': '',
                'client-auth-type': '',
                'client-auth-cert': '',
                'ech-key': '',
                'ech-cert': '',
                users: [],
                _usersText: '',
                _shadowTlsText: '',
                _kcpTunText: ''
            });
        };

        const removeListener = (idx) => {
            config.value.listeners.splice(idx, 1);
        };

        const sanitizeListenerUser = (user) => {
            if (!user || typeof user !== 'object') return { username: '', password: '' };
            return {
                username: String(user.username || '').trim(),
                password: String(user.password || '')
            };
        };

        const parseListenerUsersForEditor = (listener) => {
            if (!listener || typeof listener !== 'object') return [];
            if (Array.isArray(listener.users) && listener.users.length > 0) {
                return listener.users.map(sanitizeListenerUser);
            }

            const rawText = String(listener._usersText || '').trim();
            if (!rawText) return [];

            try {
                const parsedList = parseYamlSequenceText(rawText, (item) => item);
                if (parsedList && parsedList.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
                    return parsedList.map(sanitizeListenerUser);
                }
            } catch (err) {
                // ignore parse failures here; validation will surface the exact error
            }

            try {
                const parsedObject = parseYamlObjectText(rawText);
                if (parsedObject && typeof parsedObject === 'object' && !Array.isArray(parsedObject)) {
                    return [sanitizeListenerUser(parsedObject)];
                }
            } catch (err) {
                // ignore parse failures here; validation will surface the exact error
            }

            return [];
        };

        const syncListenerUsersText = (listener) => {
            if (!listener || typeof listener !== 'object') return;
            const editorUsers = (Array.isArray(listener.users) ? listener.users : [])
                .map(sanitizeListenerUser);
            const exportUsers = editorUsers.filter((user) => user.username || user.password);
            listener.users = editorUsers;
            listener._usersText = formatYamlSequenceText(exportUsers);
        };

        const ensureListenerUsers = (listener) => {
            if (!listener || typeof listener !== 'object') return;
            if (!Array.isArray(listener.users) || listener.users.length === 0) {
                listener.users = parseListenerUsersForEditor(listener);
            } else {
                listener.users = listener.users.map(sanitizeListenerUser);
            }
            syncListenerUsersText(listener);
        };

        const listenerUsesStructuredUsers = (listener) => ['mixed', 'http', 'socks'].includes(String(listener?.type || '').trim());

        const addListenerUser = (listener) => {
            if (!listener || typeof listener !== 'object') return;
            ensureListenerUsers(listener);
            listener.users.push({ username: '', password: '' });
            syncListenerUsersText(listener);
        };

        const removeListenerUser = (listener, userIndex) => {
            if (!listener || typeof listener !== 'object' || !Array.isArray(listener.users)) return;
            listener.users.splice(userIndex, 1);
            syncListenerUsersText(listener);
        };

        const handleListenerTypeChange = (listener) => {
            if (!listener || typeof listener !== 'object') return;
            if (String(listener.type || '').trim() === 'tunnel') {
                listener.network = normalizeTunnelListenerNetwork(listener.network);
                if (!Array.isArray(listener.network) || listener.network.length === 0) {
                    listener.network = ['tcp'];
                }
                listener.target = String(listener.target || '').trim();
                return;
            }

            if (listenerUsesStructuredUsers(listener)) {
                ensureListenerUsers(listener);
            }

            if (!Array.isArray(listener.network)) {
                listener.network = normalizeTunnelListenerNetwork(listener.network);
            }
        };

        onMounted(() => {
            if (!Array.isArray(config.value.listeners)) return;
            config.value.listeners.forEach((listener) => {
                if (listenerUsesStructuredUsers(listener)) ensureListenerUsers(listener);
            });
        });

        const shadowsocksCipherOptions = getShadowsocksCipherOptions();

        const getListenerShadowsocksPasswordPlaceholder = (cipher) => {
            const normalizedCipher = String(cipher || '').trim();
            if (!normalizedCipher) return '请先选择加密算法';
            if (normalizedCipher === 'none') return 'none 模式无需密码';
            if (isShadowsocks2022Cipher(normalizedCipher)) return '点击右侧生成标准 Base64 密钥';
            return '请输入密码或点击右侧生成';
        };

        const generateListenerShadowsocksPassword = (listener) => {
            if (!listener || typeof listener !== 'object') return;
            const cipher = String(listener.cipher || '').trim();
            if (!cipher || !isSupportedShadowsocksCipher(cipher)) return;
            listener.password = generateShadowsocksPassword(cipher);
        };

        return {
            addListener,
            removeListener,
            addListenerUser,
            removeListenerUser,
            syncListenerUsersText,
            tunnelListenerNetworkOptions: tunnelListenerNetworkOptions.slice(),
            handleListenerTypeChange,
            shadowsocksCipherOptions,
            getListenerShadowsocksPasswordPlaceholder,
            generateListenerShadowsocksPassword
        };
    };
})(window);
