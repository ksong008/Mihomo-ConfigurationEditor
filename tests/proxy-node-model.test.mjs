import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'modules/proxy-schema.js',
        'modules/proxy-node-utils.js',
        'modules/proxy-node-model.js'
    ]
});

const plain = (value) => JSON.parse(JSON.stringify(value));

test('proxy node model normalizes Snell version and psk alias', async () => {
    const runtime = await runtimePromise;
    const { parseSingleProxyNode } = runtime.window.MihomoFeatureModules.ProxyNodeModel.createProxyNodeModel();

    const parsed = plain(parseSingleProxyNode({
        name: 'snell-v5',
        type: 'snell',
        version: 'v5',
        psk: 'secret',
        udp: true,
        reuse: true
    }));

    assert.equal(parsed.name, 'snell-v5');
    assert.equal(parsed.type, 'snell');
    assert.equal(parsed.version, '5');
    assert.equal(parsed.password, 'secret');
    assert.equal(parsed.udp, true);
    assert.equal(parsed.reuse, true);
});

test('proxy node model normalizes OpenVPN imports into editable state', async () => {
    const runtime = await runtimePromise;
    const { parseSingleProxyNode } = runtime.window.MihomoFeatureModules.ProxyNodeModel.createProxyNodeModel();

    const parsed = plain(parseSingleProxyNode({
        name: 'ovpn',
        type: 'openvpn',
        proto: 'tcp-client',
        cipher: 'aes-cbc',
        auth: 'sha-1',
        dns: ['1.1.1.1', '8.8.8.8']
    }));

    assert.equal(parsed.proto, 'tcp');
    assert.equal(parsed.cipher, 'AES-128-CBC');
    assert.equal(parsed.auth, 'SHA1');
    assert.equal(parsed.dns, '1.1.1.1\n8.8.8.8');
    assert.equal(parsed.mtu, '');
});

test('proxy node model uses injected YAML formatters for editable text fields', async () => {
    const runtime = await runtimePromise;
    const model = runtime.window.MihomoFeatureModules.ProxyNodeModel.createProxyNodeModel({
        formatYamlMapText: (value) => `map:${Object.keys(value || {}).join(',')}`,
        formatYamlObjectText: (value) => `object:${Object.keys(value || {}).join(',')}`
    });

    const parsed = plain(model.parseSingleProxyNode({
        type: 'vless',
        headers: { Host: 'example.com' },
        httpmask: { enabled: true },
        'amnezia-wg-option': { jc: 4 }
    }));

    assert.equal(parsed._proxyHeadersText, 'map:Host');
    assert.equal(parsed._sudokuHttpmaskText, 'object:enabled');
    assert.equal(parsed._amneziaWgOptionText, 'object:jc');
});
