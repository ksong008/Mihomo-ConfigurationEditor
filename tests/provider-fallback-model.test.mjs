import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'core/provider-fallback-model.js'
    ]
});

const cloneJsonValue = (value, fallback = null) => {
    try {
        return JSON.parse(JSON.stringify(value));
    } catch (err) {
        return fallback;
    }
};

const sanitizeProxyNodeForYaml = (proxy) => ({
    name: proxy.name,
    type: proxy.type || 'vless',
    server: proxy.server || 'example.test'
});

const dumpYaml = (value) => JSON.stringify(value, null, 2);

test('provider fallback model normalizes selected payload names and nodes', async () => {
    const runtime = await runtimePromise;
    const { normalizeProviderFallbackPayloadState } = runtime.window.MihomoCore.ProviderFallbackModel;
    const providers = [
        {
            name: 'Remote',
            type: 'http',
            _fallbackPayloadProxyNames: [' A ', 'Detached', 'A', '', 'Missing'],
            _fallbackPayload: [
                { name: 'Detached', type: 'ss', server: 'old.example' },
                { name: 'Ignored', type: 'ss', server: 'ignored.example' }
            ]
        },
        {
            name: 'Chain',
            type: 'http',
            _chainMode: 'inline',
            _fallbackPayloadProxyNames: ['A'],
            _fallbackPayload: []
        }
    ];
    const proxies = [{ name: 'A', type: 'trojan', server: 'live.example' }];

    normalizeProviderFallbackPayloadState({
        providers,
        proxies,
        cloneJsonValue,
        sanitizeProxyNodeForYaml
    });

    assert.deepEqual(Array.from(providers[0]._fallbackPayloadProxyNames), ['A', 'Detached', 'Missing']);
    assert.deepEqual(Array.from(providers[0]._fallbackPayload), [
        { name: 'A', type: 'trojan', server: 'live.example' },
        { name: 'Detached', type: 'ss', server: 'old.example' }
    ]);
    assert.deepEqual(Array.from(providers[1]._fallbackPayloadProxyNames), ['A']);
    assert.deepEqual(Array.from(providers[1]._fallbackPayload), []);
});

test('provider fallback model reports snapshots detached from live proxies', async () => {
    const runtime = await runtimePromise;
    const {
        getProviderFallbackSnapshotNames,
        getProviderFallbackDetachedNames
    } = runtime.window.MihomoCore.ProviderFallbackModel;
    const provider = {
        _fallbackPayload: [
            { name: 'A' },
            { name: 'Detached' },
            { name: ' ' }
        ]
    };

    assert.deepEqual(Array.from(getProviderFallbackSnapshotNames(provider)), ['A', 'Detached']);
    assert.deepEqual(
        Array.from(getProviderFallbackDetachedNames({ provider, proxies: [{ name: 'A' }] })),
        ['Detached']
    );
});

test('provider fallback model removes selected and snapshot nodes by name', async () => {
    const runtime = await runtimePromise;
    const { removeProviderFallbackPayloadNode } = runtime.window.MihomoCore.ProviderFallbackModel;
    const provider = {
        _fallbackPayloadProxyNames: ['A', ' Detached ', '', 'A'],
        _fallbackPayload: [
            { name: 'A' },
            { name: 'Detached' }
        ]
    };

    removeProviderFallbackPayloadNode(provider, 'A');

    assert.deepEqual(Array.from(provider._fallbackPayloadProxyNames), ['Detached']);
    assert.deepEqual(Array.from(provider._fallbackPayload), [{ name: 'Detached' }]);
});

test('provider fallback model builds inline and fallback payload previews', async () => {
    const runtime = await runtimePromise;
    const {
        getInlinePayloadPreview,
        getProviderFallbackPayloadPreview
    } = runtime.window.MihomoCore.ProviderFallbackModel;
    const proxies = [{ name: 'A', type: 'vless', server: 'live.example' }];
    const provider = {
        _fallbackPayloadProxyNames: ['A', 'Detached'],
        _fallbackPayload: [{ name: 'Detached', type: 'ss', server: 'old.example' }]
    };

    assert.deepEqual(
        JSON.parse(getInlinePayloadPreview({ inlineProxies: ['A'], proxies, sanitizeProxyNodeForYaml, dumpYaml })),
        [{ name: 'A', type: 'vless', server: 'live.example' }]
    );
    assert.deepEqual(
        JSON.parse(getProviderFallbackPayloadPreview({ provider, proxies, cloneJsonValue, sanitizeProxyNodeForYaml, dumpYaml })),
        [
            { name: 'A', type: 'vless', server: 'live.example' },
            { name: 'Detached', type: 'ss', server: 'old.example' }
        ]
    );
    assert.equal(getInlinePayloadPreview({ inlineProxies: [], proxies, sanitizeProxyNodeForYaml, dumpYaml }), '[]');
    assert.equal(getProviderFallbackPayloadPreview({ provider: null, proxies, cloneJsonValue, sanitizeProxyNodeForYaml, dumpYaml }), '[]');
});
