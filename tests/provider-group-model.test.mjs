import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'core/provider-group-model.js'
    ]
});

test('provider group model builds candidate members in UI order', async () => {
    const runtime = await runtimePromise;
    const {
        BUILTIN_PROXY_TARGETS,
        getAvailableGroupMembers,
        getAvailableEmptyFallbackMembers
    } = runtime.window.MihomoCore.ProviderGroupModel;

    const proxies = [
        { name: '  Manual A ' },
        { name: '' },
        { name: 'Manual B' }
    ];
    const groups = [
        { name: 'Current' },
        { name: 'Other' },
        { name: ' ' }
    ];

    assert.deepEqual(
        Array.from(getAvailableGroupMembers({ proxies, groups, currentGroupName: 'Current' })),
        [...BUILTIN_PROXY_TARGETS, 'Other', 'Manual A', 'Manual B']
    );
    assert.deepEqual(
        Array.from(getAvailableEmptyFallbackMembers(proxies)),
        [...BUILTIN_PROXY_TARGETS, 'Manual A', 'Manual B']
    );
});

test('provider group model keeps selected valid members at the top', async () => {
    const runtime = await runtimePromise;
    const {
        getOrderedAvailableGroupMembers,
        getOrderedGroupUseProviders
    } = runtime.window.MihomoCore.ProviderGroupModel;

    const proxies = [{ name: 'A' }, { name: 'B' }];
    const groups = [{ name: 'Current', proxies: ['B', 'DIRECT', 'Missing', 'B'] }, { name: 'Other' }];
    const providers = [{ name: 'Remote A' }, { name: 'Remote B' }];

    assert.deepEqual(
        Array.from(getOrderedAvailableGroupMembers({ group: groups[0], proxies, groups })),
        ['B', 'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'COMPATIBLE', 'Other', 'A']
    );
    assert.deepEqual(
        Array.from(getOrderedGroupUseProviders({ group: { use: ['Remote B', 'Missing'] }, providers })),
        ['Remote B', 'Remote A']
    );
});

test('provider group model prunes invalid proxy and provider members', async () => {
    const runtime = await runtimePromise;
    const {
        pruneInvalidGroupProxyMembers,
        pruneInvalidGroupUseMembers
    } = runtime.window.MihomoCore.ProviderGroupModel;

    const proxies = [{ name: 'A' }];
    const groups = [
        { name: 'Group A', proxies: ['A', 'Group B', 'Missing', 'DIRECT'], use: ['Remote', 'Missing'] },
        { name: 'Group B', proxies: 'bad', use: 'bad' }
    ];
    const providers = [{ name: 'Remote' }];

    pruneInvalidGroupProxyMembers({ proxies, groups });
    pruneInvalidGroupUseMembers({ groups, providers });

    assert.deepEqual(groups[0].proxies, ['A', 'Group B', 'DIRECT']);
    assert.deepEqual(groups[0].use, ['Remote']);
    assert.deepEqual(Array.from(groups[1].proxies), []);
    assert.deepEqual(Array.from(groups[1].use), []);
});

test('provider group model detects include-all proxy and provider modes', async () => {
    const runtime = await runtimePromise;
    const {
        groupIncludesAllProxies,
        groupIncludesAllProviders
    } = runtime.window.MihomoCore.ProviderGroupModel;

    assert.equal(groupIncludesAllProxies({ 'include-all': true }), true);
    assert.equal(groupIncludesAllProxies({ 'include-all-proxies': true }), true);
    assert.equal(groupIncludesAllProxies({ 'include-all-providers': true }), false);
    assert.equal(groupIncludesAllProviders({ 'include-all': true }), true);
    assert.equal(groupIncludesAllProviders({ 'include-all-providers': true }), true);
    assert.equal(groupIncludesAllProviders({ 'include-all-proxies': true }), false);
});
