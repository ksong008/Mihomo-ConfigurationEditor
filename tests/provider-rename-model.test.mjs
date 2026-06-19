import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'core/provider-rename-model.js'
    ]
});

test('provider rename tracker propagates provider name references', async () => {
    const runtime = await runtimePromise;
    const { createProviderRenameTracker } = runtime.window.MihomoCore.ProviderRenameModel;
    const tracker = createProviderRenameTracker();
    const provider = { name: 'Remote' };
    const providers = [
        provider,
        { name: 'Chain', _sourceProviderName: 'Remote' }
    ];
    const groups = [
        { name: 'Proxy', use: ['Remote', 'Other'] }
    ];

    tracker.ensureSnapshots({ providers, groups });
    tracker.updateProviderName({
        provider,
        newName: 'Remote Next',
        providers,
        groups
    });

    assert.equal(provider.name, 'Remote Next');
    assert.deepEqual(Array.from(groups[0].use), ['Remote Next', 'Other']);
    assert.equal(providers[1]._sourceProviderName, 'Remote Next');
});

test('provider rename tracker propagates proxy name references', async () => {
    const runtime = await runtimePromise;
    const { createProviderRenameTracker } = runtime.window.MihomoCore.ProviderRenameModel;
    const tracker = createProviderRenameTracker();
    const proxy = { name: 'Node A', 'dialer-proxy': 'Self Should Stay' };
    const proxies = [
        proxy,
        { name: 'Node B', 'dialer-proxy': 'Node A' }
    ];
    const groups = [
        { name: 'Proxy', proxies: ['Node A', 'DIRECT'] }
    ];
    const providers = [
        {
            name: 'Remote',
            proxy: 'Node A',
            overrideDialerProxy: 'Node A',
            inlineProxies: ['Node A'],
            _fallbackPayloadProxyNames: ['Node A'],
            _fallbackPayload: [{ name: 'Node A' }]
        }
    ];
    const ruleProviders = [{ name: 'Rules', proxy: 'Node A' }];
    const rules = [{ type: 'DOMAIN', value: 'example.com', target: 'Node A' }];

    tracker.ensureSnapshots({ providers, proxies, groups });
    tracker.updateProxyName({
        proxy,
        newName: 'Node Next',
        providers,
        ruleProviders,
        proxies,
        groups,
        rules
    });

    assert.equal(proxy.name, 'Node Next');
    assert.equal(proxy['dialer-proxy'], 'Self Should Stay');
    assert.equal(proxies[1]['dialer-proxy'], 'Node Next');
    assert.deepEqual(Array.from(groups[0].proxies), ['Node Next', 'DIRECT']);
    assert.equal(providers[0].proxy, 'Node Next');
    assert.equal(providers[0].overrideDialerProxy, 'Node Next');
    assert.deepEqual(Array.from(providers[0].inlineProxies), ['Node Next']);
    assert.deepEqual(Array.from(providers[0]._fallbackPayloadProxyNames), ['Node Next']);
    assert.equal(providers[0]._fallbackPayload[0].name, 'Node Next');
    assert.equal(ruleProviders[0].proxy, 'Node Next');
    assert.equal(rules[0].target, 'Node Next');
});

test('provider rename tracker propagates group name references and removes self-reference', async () => {
    const runtime = await runtimePromise;
    const { createProviderRenameTracker } = runtime.window.MihomoCore.ProviderRenameModel;
    const tracker = createProviderRenameTracker();
    const group = { name: 'Auto', proxies: ['Auto', 'Node A'] };
    const groups = [
        group,
        { name: 'Proxy', proxies: ['Auto', 'DIRECT'] }
    ];
    const proxies = [{ name: 'Node A', 'dialer-proxy': 'Auto' }];
    const providers = [{ name: 'Remote', proxy: 'Auto', overrideDialerProxy: 'Auto' }];
    const ruleProviders = [{ name: 'Rules', proxy: 'Auto' }];
    const rules = [{ type: 'MATCH', target: 'Auto' }];

    tracker.ensureSnapshots({ providers, proxies, groups });
    tracker.updateGroupName({
        group,
        newName: 'Auto Next',
        providers,
        ruleProviders,
        proxies,
        groups,
        rules
    });

    assert.equal(group.name, 'Auto Next');
    assert.deepEqual(Array.from(group.proxies), ['Node A']);
    assert.deepEqual(Array.from(groups[1].proxies), ['Auto Next', 'DIRECT']);
    assert.equal(proxies[0]['dialer-proxy'], 'Auto Next');
    assert.equal(providers[0].proxy, 'Auto Next');
    assert.equal(providers[0].overrideDialerProxy, 'Auto Next');
    assert.equal(ruleProviders[0].proxy, 'Auto Next');
    assert.equal(rules[0].target, 'Auto Next');
});

test('provider rename tracker refreshes snapshots after each rename', async () => {
    const runtime = await runtimePromise;
    const { createProviderRenameTracker } = runtime.window.MihomoCore.ProviderRenameModel;
    const tracker = createProviderRenameTracker();
    const proxy = { name: 'A' };
    const groups = [{ name: 'Proxy', proxies: ['A'] }];
    const proxies = [proxy];

    tracker.ensureSnapshots({ proxies, groups });
    tracker.updateProxyName({ proxy, newName: 'B', proxies, groups, providers: [], ruleProviders: [], rules: [] });
    tracker.updateProxyName({ proxy, newName: 'C', proxies, groups, providers: [], ruleProviders: [], rules: [] });

    assert.deepEqual(Array.from(groups[0].proxies), ['C']);
});
