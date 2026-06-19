import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'mihomo.helpers.js',
        'core/import-model.js'
    ]
});

const plain = (value) => JSON.parse(JSON.stringify(value));

function createImportModel(runtime) {
    const helpers = runtime.window.MihomoHelpers;
    return runtime.window.MihomoCore.ImportModel.createImportModel({
        parseYamlMapText: helpers.parseYamlMapText,
        parseYamlSequenceText: helpers.parseYamlSequenceText,
        parseYamlObjectText: helpers.parseYamlObjectText,
        formatYamlSequenceText: helpers.formatYamlSequenceText,
        formatYamlObjectText: helpers.formatYamlObjectText,
        normalizeTunnelListenerNetwork: helpers.normalizeTunnelListenerNetwork
    });
}

test('import model normalizes list-like config sections', async () => {
    const runtime = await runtimePromise;
    const model = createImportModel(runtime);
    const normalized = plain(model.normalizeImportedConfigData({
        dns: {
            nameserver: 'https://dns.example/dns-query\n# ignored\n1.1.1.1',
            'fake-ip-filter': ['RULE-SET,geo-cn,fake-ip']
        },
        rules: [
            ['DOMAIN-SUFFIX', 'example.com', 'Proxy'],
            { type: 'MATCH', target: 'DIRECT' }
        ],
        listeners: [{
            type: 'tunnel',
            port: 5300,
            network: 'tcp, udp',
            users: [{ username: 'u', password: 'p' }]
        }]
    }));

    assert.deepEqual(normalized.dns.nameserver, ['https://dns.example/dns-query', '1.1.1.1']);
    assert.deepEqual(normalized.rules, ['DOMAIN-SUFFIX,example.com,Proxy', 'MATCH,DIRECT']);
    assert.equal(normalized.listeners[0].name, 'listener-1');
    assert.deepEqual(normalized.listeners[0].network, ['tcp', 'udp']);
    assert.match(normalized.listeners[0]._usersText, /username/);
});

test('import model normalizes providers and override fields', async () => {
    const runtime = await runtimePromise;
    const model = createImportModel(runtime);
    const normalized = plain(model.normalizeImportedConfigData({
        'proxy-providers': {
            remote: {
                type: 'http',
                url: 'https://example.com/sub.yaml',
                header: '{"Authorization":"Bearer token"}',
                override: {
                    udp: true,
                    'proxy-name': [{ pattern: '^(.*)$', target: 'pre-$1' }],
                    up: 50
                },
                payload: [{ name: 'fallback-node', type: 'ss' }]
            }
        },
        'rule-providers': {
            geo: {
                type: 'inline',
                payload: 'DOMAIN-SUFFIX,example.com'
            }
        }
    }));

    assert.equal(normalized['proxy-providers'].remote.type, 'http');
    assert.equal(normalized['proxy-providers'].remote.override.udp, true);
    assert.deepEqual(normalized['proxy-providers'].remote.override['proxy-name'], [{ pattern: '^(.*)$', target: 'pre-$1' }]);
    assert.equal(normalized['proxy-providers'].remote.override.up, '50');
    assert.deepEqual(normalized['rule-providers'].geo.payload, ['DOMAIN-SUFFIX,example.com']);
});

test('import model exposes shared helpers used by import/export state flow', async () => {
    const runtime = await runtimePromise;
    const model = createImportModel(runtime);

    assert.deepEqual(plain(model.ensureArray({ a: 1, b: 2 })), [1, 2]);
    assert.equal(model.listToMultilineText(['a', ' b ', '']), 'a\nb');
    assert.equal(model.formatProviderOverrideBooleanValue(true), 'true');
    assert.equal(model.formatProviderOverrideBooleanValue(false), 'false');
});
