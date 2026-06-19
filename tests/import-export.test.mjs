import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { createRuntime, ROOT } from './support/runtime-harness.mjs';

async function readFixture(name) {
    const text = await readFile(path.join(ROOT, 'tests', 'fixtures', name), 'utf8');
    return JSON.parse(text);
}

function createImportHarness(runtime) {
    const { getDefaultConfig, getDefaultUiState } = runtime.window.MihomoCore.createStateModule();
    const config = { value: getDefaultConfig() };
    const uiState = { value: getDefaultUiState() };
    const providersList = { value: [] };
    const ruleProvidersList = { value: [] };
    const crashError = { value: null };
    const fullYaml = { value: '' };
    const runtimeValidationErrors = { value: [] };
    const proxiesModule = runtime.window.MihomoFeatureModules.createProxiesModule();
    const rulesModule = runtime.window.MihomoFeatureModules.createRulesModule({
        ref: (value) => ({ value }),
        config,
        uiState,
        scrollToBottom: () => {}
    });
    const importExportModule = runtime.window.MihomoCore.createImportExportModule({
        config,
        uiState,
        providersList,
        ruleProvidersList,
        fileInput: { value: { click: () => {} } },
        fullYaml,
        crashError,
        runtimeValidationErrors,
        getDefaultConfig,
        safeBuildYaml: () => true,
        parseSingleProxyNode: proxiesModule.parseSingleProxyNode,
        formatYamlMapText: runtime.window.MihomoHelpers.formatYamlMapText,
        parseRuleString: rulesModule.parseRuleString,
        scrollToBottom: () => {},
        ensureGroupCollapseState: () => {},
        ensureRuleProviderCollapseState: () => {},
        pruneInvalidGroupProxyMembers: () => {},
        pruneInvalidGroupUseMembers: () => {}
    });

    return {
        config,
        uiState,
        providersList,
        ruleProvidersList,
        importExportModule
    };
}

const runtimePromise = createRuntime({
    scripts: [
        'mihomo.helpers.js',
        'core/state.js',
        'modules/proxy-schema.js',
        'modules/proxy-node-utils.js',
        'modules/proxy-node-model.js',
        'modules/proxy-node-validation.js',
        'modules/proxy-node-yaml.js',
        'modules/proxies.js',
        'modules/rule-parser.js',
        'modules/rules.js',
        'core/import-export.js'
    ]
});

test('import keeps current Meta config fields in editable state', async () => {
    const runtime = await runtimePromise;
    const fixture = await readFixture('meta-config.json');
    const { config, uiState, providersList, ruleProvidersList, importExportModule } = createImportHarness(runtime);

    importExportModule.applyYamlImport(fixture);

    assert.equal(config.value.dns.enable, true);
    assert.equal(config.value.dns.listen, ':1053');
    assert.equal(config.value.dns['cache-max-size'], 4096);
    assert.equal(config.value.dns['ipv6-timeout'], 300);
    assert.equal(uiState.value.dnsNameservers, 'https://dns.alidns.com/dns-query');

    const tlsNode = config.value.proxies.find((proxy) => proxy.name === 'tls-node');
    assert.equal(tlsNode['client-fingerprint'], 'chrome');

    const snellNode = config.value.proxies.find((proxy) => proxy.name === 'snell-v5');
    assert.equal(snellNode.version, '5');
    assert.equal(snellNode.udp, true);
    assert.equal(snellNode.reuse, true);

    const openvpnNode = config.value.proxies.find((proxy) => proxy.name === 'ovpn');
    assert.equal(openvpnNode.type, 'openvpn');
    assert.equal(openvpnNode.proto, 'tcp');
    assert.equal(openvpnNode.cipher, 'AES-256-GCM');
    assert.equal(openvpnNode.auth, 'SHA512');
    assert.equal(openvpnNode['remote-dns-resolve'], true);
    assert.equal(openvpnNode.dns, '1.1.1.1');

    assert.equal(providersList.value.length, 1);
    assert.equal(providersList.value[0].name, 'remote');
    assert.equal(providersList.value[0].ageSecretKey, 'AGE-SECRET-KEY-demo');
    assert.equal(providersList.value[0].overrideTfo, 'true');
    assert.equal(providersList.value[0].overrideIpVersion, 'ipv4');

    assert.equal(ruleProvidersList.value.length, 1);
    assert.equal(ruleProvidersList.value[0].name, 'geo-cn');
    assert.equal(ruleProvidersList.value[0].pathInBundle, 'geo/geosite/cn.mrs');

    assert.equal(config.value['proxy-groups'].length, 1);
    assert.equal(config.value['proxy-groups'][0]['empty-fallback'], 'DIRECT');
    assert.deepEqual(Array.from(config.value['proxy-groups'][0].use), ['remote']);

    assert.equal(uiState.value.rules.length, 2);
    assert.equal(uiState.value.rules[0].type, 'RULE-SET');
    assert.equal(uiState.value.rules[0].value, 'geo-cn');
    assert.equal(uiState.value.rules[0].target, 'PASS-RULE');
    assert.equal(uiState.value.rules[1].type, 'MATCH');
    assert.equal(uiState.value.rules[1].target, 'Auto');
});
