import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'modules/proxy-schema.js',
        'modules/proxy-node-utils.js'
    ]
});

const plain = (value) => JSON.parse(JSON.stringify(value));

test('proxy node utils normalize OpenVPN aliases', async () => {
    const runtime = await runtimePromise;
    const utils = runtime.window.MihomoFeatureModules.ProxyNodeUtils;

    assert.equal(utils.normalizeOpenvpnProtoValue('udp4'), 'udp');
    assert.equal(utils.normalizeOpenvpnProtoValue('tcp-client'), 'tcp');
    assert.equal(utils.normalizeOpenvpnCipherValue('aes-cbc'), 'AES-128-CBC');
    assert.equal(utils.normalizeOpenvpnAuthValue('sha-1'), 'SHA1');
    assert.equal(utils.normalizeOpenvpnCompLzoValue(' ADAPTIVE '), 'adaptive');
});

test('proxy node utils parse scalar lists and validate port ranges', async () => {
    const runtime = await runtimePromise;
    const utils = runtime.window.MihomoFeatureModules.ProxyNodeUtils;

    assert.deepEqual(plain(utils.parseScalarListText('h2, h3\nhttp/1.1')), ['h2', 'h3', 'http/1.1']);
    assert.equal(utils.formatScalarListText(['h2', '', ' http/1.1 ']), 'h2\nhttp/1.1');
    assert.equal(utils.isValidPortRangeListText('40000-50000,60000/60010-60020'), true);
    assert.equal(utils.isValidPortRangeListText('0-1'), false);
    assert.equal(utils.isValidHy2HopIntervalText('15-30'), true);
    assert.equal(utils.isValidHy2HopIntervalText('30-15'), false);
    assert.equal(utils.isValidPositiveIntegerOrRangeText('64-128'), true);
    assert.equal(utils.isValidIntegerText('-1', { allowNegative: true }), true);
    assert.equal(utils.isValidIntegerText('-1'), false);
});

test('proxy node utils sanitize xHTTP download settings', async () => {
    const runtime = await runtimePromise;
    const utils = runtime.window.MihomoFeatureModules.ProxyNodeUtils;

    const sanitized = utils.sanitizeXhttpDownloadSettings({
        path: '/download',
        unknown: true,
        'reuse-settings': {
            'max-concurrency': '16-32',
            unsupported: 'ignored'
        }
    });

    assert.deepEqual(plain(sanitized), {
        path: '/download',
        'reuse-settings': {
            'max-concurrency': '16-32'
        }
    });
    assert.deepEqual(
        plain(
        utils.collectUnsupportedXhttpDownloadSettingsKeys({
            extra: true,
            'reuse-settings': { unsupported: true }
        })),
        ['extra', 'reuse-settings.unsupported']
    );
});

test('proxy node utils compact YAML values against defaults', async () => {
    const runtime = await runtimePromise;
    const utils = runtime.window.MihomoFeatureModules.ProxyNodeUtils;

    const compacted = utils.compactWithDefaults({
        name: 'Node',
        type: 'vless',
        port: 443,
        udp: true,
        empty: '',
        nested: {
            keep: 'x',
            drop: false
        },
        list: ['a', '', null]
    }, {
        type: 'vless',
        port: 443,
        udp: true,
        nested: {
            drop: false
        }
    }, new Set(['name', 'type', 'port']));

    assert.deepEqual(plain(compacted), {
        name: 'Node',
        type: 'vless',
        port: 443,
        nested: {
            keep: 'x'
        },
        list: ['a']
    });
});
