import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const dumpLikeYaml = (value) => JSON.stringify(value, null, 2);

async function loadBrowserScript(context, relativePath) {
    const source = await readFile(path.join(ROOT, relativePath), 'utf8');
    vm.runInContext(source, context, { filename: relativePath });
}

async function createRuntime() {
    const sandbox = {
        console,
        Buffer,
        Uint8Array,
        atob: globalThis.atob,
        btoa: globalThis.btoa,
        crypto: globalThis.crypto,
        setTimeout,
        clearTimeout,
        alert: () => {},
        navigator: {
            clipboard: {
                writeText: async () => {}
            }
        }
    };

    sandbox.window = {
        crypto: globalThis.crypto
    };
    sandbox.window.window = sandbox.window;
    sandbox.window.globalThis = sandbox;

    sandbox.jsyaml = {
        dump: dumpLikeYaml,
        load: JSON.parse
    };
    sandbox.window.jsyaml = sandbox.jsyaml;
    sandbox.globalThis = sandbox;

    const context = vm.createContext(sandbox);
    await loadBrowserScript(context, 'mihomo.helpers.js');
    await loadBrowserScript(context, 'core/state.js');
    await loadBrowserScript(context, 'modules/tproxy.js');
    await loadBrowserScript(context, 'modules/yaml.js');

    return context;
}

function createYamlHarness(runtime) {
    const { getDefaultConfig, getDefaultUiState } = runtime.window.MihomoCore.createStateModule();
    const config = { value: getDefaultConfig() };
    const uiState = { value: getDefaultUiState() };
    const providersList = { value: [] };
    const ruleProvidersList = { value: [] };
    const yamlModule = runtime.window.MihomoFeatureModules.createYamlModule({
        ref: (value) => ({ value }),
        config,
        uiState,
        providersList,
        ruleProvidersList,
        sanitizeProxyNodeForYaml: (proxy) => proxy,
        getRuleProviderUrl: () => '',
        getDefaultConfig
    });

    return {
        config,
        uiState,
        yamlModule
    };
}

function createTproxyHarness(runtime) {
    const { getDefaultConfig, getDefaultUiState } = runtime.window.MihomoCore.createStateModule();
    const config = { value: getDefaultConfig() };
    const uiState = { value: getDefaultUiState() };

    const tproxyModule = runtime.window.MihomoFeatureModules.createTproxyModule({
        watch: (source, cb, options = {}) => {
            if (options.immediate) cb(source());
        },
        computed: (getter) => ({
            get value() {
                return getter();
            }
        }),
        config,
        uiState,
        dnsListenPort: { value: 53 },
        ensureSafeDnsListenPortForTransparentProxy: () => false
    });

    return {
        config,
        uiState,
        tproxyModule
    };
}

const runtimePromise = createRuntime();

test('shadowsocks helper generates standard passwords for supported ciphers', async () => {
    const runtime = await runtimePromise;
    const helpers = runtime.window.MihomoHelpers;

    const ss2022Key128 = helpers.generateShadowsocksPassword('2022-blake3-aes-128-gcm');
    const ss2022Key256 = helpers.generateShadowsocksPassword('2022-blake3-aes-256-gcm');
    const ss2022ChachaKey = helpers.generateShadowsocksPassword('2022-blake3-chacha20-poly1305');
    const legacyPassword = helpers.generateShadowsocksPassword('aes-128-gcm');

    assert.equal(Buffer.from(ss2022Key128, 'base64').length, 16);
    assert.equal(Buffer.from(ss2022Key256, 'base64').length, 32);
    assert.equal(Buffer.from(ss2022ChachaKey, 'base64').length, 32);
    assert.match(legacyPassword, /^[A-Za-z0-9_-]{24}$/);
    assert.equal(helpers.generateShadowsocksPassword('none'), '');

    assert.equal(helpers.isValidShadowsocksPasswordForCipher('2022-blake3-aes-128-gcm', ss2022Key128), true);
    assert.equal(helpers.isValidShadowsocksPasswordForCipher('2022-blake3-aes-128-gcm', ss2022Key256), false);
    assert.equal(helpers.isValidShadowsocksPasswordForCipher('none', ''), true);
    assert.equal(helpers.isValidShadowsocksPasswordForCipher('none', 'demo'), false);
});

test('listener port helper avoids collisions with base ports and listeners', async () => {
    const runtime = await runtimePromise;
    const helpers = runtime.window.MihomoHelpers;
    const { getDefaultConfig, getDefaultUiState } = runtime.window.MihomoCore.createStateModule();

    const config = getDefaultConfig();
    const uiState = getDefaultUiState();

    assert.equal(helpers.getSuggestedListenerPort(config, uiState, 7895), 7895);

    config.listeners.push({ port: '7895' }, { port: '7896-7898' });
    assert.equal(helpers.getSuggestedListenerPort(config, uiState, 7895), 7899);
    assert.deepEqual(Array.from(helpers.normalizeTunnelListenerNetwork('tcp, udp udp')), ['tcp', 'udp']);
});

test('default yaml omits tproxy-only general keys', async () => {
    const runtime = await runtimePromise;
    const { yamlModule } = createYamlHarness(runtime);

    yamlModule.buildYaml();

    assert.doesNotMatch(yamlModule.fullYaml.value, /"tproxy-port"/);
    assert.doesNotMatch(yamlModule.fullYaml.value, /"routing-mark"/);
});

test('manual routing mark is preserved without enabling tproxy', async () => {
    const runtime = await runtimePromise;
    const { config, yamlModule } = createYamlHarness(runtime);

    config.value['routing-mark'] = '2048';
    yamlModule.buildYaml();

    assert.match(yamlModule.fullYaml.value, /"routing-mark": 2048/);
    assert.doesNotMatch(yamlModule.fullYaml.value, /"tproxy-port"/);
});

test('enabled tproxy and shadowsocks listener export expected fields', async () => {
    const runtime = await runtimePromise;
    const { config, uiState, yamlModule } = createYamlHarness(runtime);
    const helpers = runtime.window.MihomoHelpers;
    const listenerPassword = helpers.generateShadowsocksPassword('2022-blake3-aes-128-gcm');

    uiState.value.tproxyEnable = true;
    uiState.value.nftablesConfig.routeMarkHex = '112';
    config.value.listeners.push({
        name: 'ss-in',
        type: 'shadowsocks',
        port: 8388,
        listen: '::',
        udp: true,
        cipher: '2022-blake3-aes-128-gcm',
        password: listenerPassword,
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

    yamlModule.buildYaml();

    assert.match(yamlModule.fullYaml.value, /"tproxy-port": 7894/);
    assert.match(yamlModule.fullYaml.value, /"routing-mark": 112/);
    assert.match(yamlModule.fullYaml.value, /"type": "shadowsocks"/);
    assert.match(yamlModule.fullYaml.value, /"cipher": "2022-blake3-aes-128-gcm"/);
    assert.match(yamlModule.fullYaml.value, new RegExp(listenerPassword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('tunnel listener exports network list and target', async () => {
    const runtime = await runtimePromise;
    const { config, yamlModule } = createYamlHarness(runtime);

    config.value.listeners.push({
        name: 'dns-tunnel',
        type: 'tunnel',
        port: '5300',
        listen: '::',
        network: ['tcp', 'udp'],
        target: '8.8.8.8:53',
        rule: '',
        proxy: '',
        token: '',
        cipher: '',
        password: '',
        users: [],
        _usersText: '',
        _shadowTlsText: '',
        _kcpTunText: ''
    });

    yamlModule.buildYaml();

    assert.match(yamlModule.fullYaml.value, /"type": "tunnel"/);
    assert.match(yamlModule.fullYaml.value, /"network": \[/);
    assert.match(yamlModule.fullYaml.value, /"tcp"/);
    assert.match(yamlModule.fullYaml.value, /"udp"/);
    assert.match(yamlModule.fullYaml.value, /"target": "8.8.8.8:53"/);
});

test('fake-ip with dns ipv6 auto-emits fake-ip-range6', async () => {
    const runtime = await runtimePromise;
    const { config, yamlModule } = createYamlHarness(runtime);

    config.value.dns.enable = true;
    config.value.dns['enhanced-mode'] = 'fake-ip';
    config.value.dns.ipv6 = true;
    config.value.dns['fake-ip-range6'] = '';

    yamlModule.buildYaml();

    assert.match(yamlModule.fullYaml.value, /"fake-ip-range6": "fc00::\/18"/);
});

test('clean nft export uses block ruleset with define-based interfaces', async () => {
    const runtime = await runtimePromise;
    const { config, uiState, tproxyModule } = createTproxyHarness(runtime);

    uiState.value.tproxyEnable = true;
    uiState.value.nftablesConfig.ingressIface = 'br-lan';
    uiState.value.nftablesConfig.egressIface = 'eth0';
    config.value.dns.listen = ':53';

    const script = tproxyModule.cleanNftablesScript.value;

    assert.match(script, /^#!\/usr\/sbin\/nft -f/m);
    assert.match(script, /^define INGRESS_IFACE = "br-lan"$/m);
    assert.match(script, /^define EGRESS_IFACE  = "eth0"$/m);
    assert.match(script, /^destroy table inet mihomo$/m);
    assert.match(script, /^table inet mihomo \{$/m);
    assert.match(script, /^\s+chain prerouting_tproxy \{$/m);
    assert.doesNotMatch(script, /^add rule /m);
});
