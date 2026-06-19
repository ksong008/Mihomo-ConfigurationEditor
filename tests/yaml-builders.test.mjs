import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'mihomo.helpers.js',
        'modules/yaml-builders.js'
    ]
});

const plain = (value) => JSON.parse(JSON.stringify(value));

test('yaml builders prune empty values and internal UI keys', async () => {
    const runtime = await runtimePromise;
    const { pruneEmptyYamlValue } = runtime.window.MihomoFeatureModules.YamlBuilders;
    const pruned = plain(pruneEmptyYamlValue({
        keep: 'value',
        empty: '',
        nil: null,
        _ui: 'hidden',
        nested: {
            keep: true,
            empty: ''
        },
        list: ['a', '', null, 'b']
    }));

    assert.deepEqual(pruned, {
        keep: 'value',
        nested: { keep: true },
        list: ['a', 'b']
    });
});

test('yaml builders strip default false flags without dropping true values', async () => {
    const runtime = await runtimePromise;
    const { stripDefaultFalseFlags } = runtime.window.MihomoFeatureModules.YamlBuilders;
    const stripped = plain(stripDefaultFalseFlags({
        udp: false,
        tls: true,
        nested: {
            enabled: false,
            value: 'x'
        }
    }, {
        udp: false,
        tls: false,
        nested: {
            enabled: false
        }
    }));

    assert.deepEqual(stripped, {
        tls: true,
        nested: {
            value: 'x'
        }
    });
});

test('yaml builders sanitize supported and unknown listeners', async () => {
    const runtime = await runtimePromise;
    const { sanitizeListenerForYaml } = runtime.window.MihomoFeatureModules.YamlBuilders;

    assert.deepEqual(plain(sanitizeListenerForYaml({
        name: 'tun-in',
        type: 'tunnel',
        listen: '::',
        port: 5300,
        network: ['tcp', 'udp'],
        target: '8.8.8.8:53',
        _usersText: 'ignored'
    })), {
        name: 'tun-in',
        type: 'tunnel',
        listen: '::',
        port: 5300,
        network: ['tcp', 'udp'],
        target: '8.8.8.8:53'
    });

    assert.deepEqual(plain(sanitizeListenerForYaml({
        name: 'custom-in',
        type: 'custom',
        port: 9000,
        extra: true,
        _usersText: 'ignored'
    })), {
        name: 'custom-in',
        type: 'custom',
        port: 9000,
        extra: true
    });
});
