import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'modules/proxy-schema.js',
        'modules/proxy-node-utils.js',
        'modules/proxy-node-model.js',
        'modules/proxy-node-yaml.js'
    ]
});

const plain = (value) => JSON.parse(JSON.stringify(value));

function createYamlSanitizer(runtime) {
    const { parseSingleProxyNode } = runtime.window.MihomoFeatureModules.ProxyNodeModel.createProxyNodeModel();
    return runtime.window.MihomoFeatureModules.ProxyNodeYaml.createProxyNodeYaml({
        parseSingleProxyNode,
        parseYamlMapText: (text) => {
            if (!String(text || '').trim()) return undefined;
            return JSON.parse(text);
        },
        parseYamlObjectText: (text) => {
            if (!String(text || '').trim()) return undefined;
            return JSON.parse(text);
        }
    });
}

test('proxy node yaml exports Snell psk alias and version-gated reuse', async () => {
    const runtime = await runtimePromise;
    const { sanitizeProxyNodeForYaml } = createYamlSanitizer(runtime);

    const sanitized = plain(sanitizeProxyNodeForYaml({
        name: 'snell-v5',
        type: 'snell',
        server: 'example.com',
        port: 443,
        version: '5',
        password: 'secret',
        udp: true,
        reuse: true
    }));

    assert.equal(sanitized.psk, 'secret');
    assert.equal(sanitized.password, undefined);
    assert.equal(sanitized.version, '5');
    assert.equal(sanitized.reuse, true);
});

test('proxy node yaml preserves websocket headers from editable text', async () => {
    const runtime = await runtimePromise;
    const { sanitizeProxyNodeForYaml } = createYamlSanitizer(runtime);

    const sanitized = plain(sanitizeProxyNodeForYaml({
        name: 'vless-ws',
        type: 'vless',
        server: 'example.com',
        port: 443,
        uuid: '00000000-0000-0000-0000-000000000000',
        network: 'ws',
        tls: true,
        'ws-opts': {
            path: '/ws',
            headers: {}
        },
        _wsHeadersText: '{"Host":"cdn.example.com"}'
    }));

    assert.equal(sanitized.network, 'ws');
    assert.deepEqual(sanitized['ws-opts'].headers, { Host: 'cdn.example.com' });
    assert.equal(sanitized.uuid, '00000000-0000-0000-0000-000000000000');
});
