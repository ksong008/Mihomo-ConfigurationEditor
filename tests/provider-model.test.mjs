import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'core/provider-model.js'
    ]
});

test('provider model creates default proxy provider state', async () => {
    const runtime = await runtimePromise;
    const { createProviderState } = runtime.window.MihomoCore.ProviderModel;
    const provider = createProviderState({ name: 'Remote' });

    assert.equal(provider.name, 'Remote');
    assert.equal(provider.type, 'http');
    assert.equal(provider.interval, 3600);
    assert.equal(provider.healthCheckEnable, true);
    assert.equal(provider.healthCheckLazy, true);
    assert.equal(provider.healthCheckTimeout, 5000);
    assert.deepEqual(Array.from(provider.inlineProxies), []);
    assert.deepEqual(Array.from(provider._fallbackPayloadProxyNames), []);
});

test('provider model supports chain provider overrides without sharing arrays', async () => {
    const runtime = await runtimePromise;
    const { createProviderState } = runtime.window.MihomoCore.ProviderModel;
    const first = createProviderState({ name: 'Chain', type: 'inline', _chainMode: 'inline' });
    const second = createProviderState({ name: 'Other' });

    first.inlineProxies.push('A');

    assert.equal(first._chainMode, 'inline');
    assert.equal(first.type, 'inline');
    assert.deepEqual(Array.from(first.inlineProxies), ['A']);
    assert.deepEqual(Array.from(second.inlineProxies), []);
});

test('provider model creates rule provider state and URLs', async () => {
    const runtime = await runtimePromise;
    const { createRuleProviderState, getRuleProviderUrl } = runtime.window.MihomoCore.ProviderModel;
    const ruleProvider = createRuleProviderState({
        file: 'cn',
        behavior: 'ipcidr',
        format: 'mrs'
    });

    assert.equal(ruleProvider.type, 'http');
    assert.equal(ruleProvider.interval, 86400);
    assert.equal(ruleProvider.autoUrl, true);
    assert.equal(ruleProvider.pathInBundle, '');
    assert.equal(
        getRuleProviderUrl(ruleProvider, { useMirrorForRuleProviders: false }),
        'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs'
    );
    assert.equal(
        getRuleProviderUrl({ ...ruleProvider, format: 'text' }, { useMirrorForRuleProviders: true }),
        'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.list'
    );
});
