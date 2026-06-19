import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'modules/validation-helpers.js'
    ]
});

test('validation helpers normalize text and split non-comment lines', async () => {
    const runtime = await runtimePromise;
    const helpers = runtime.window.MihomoFeatureModules.ValidationHelpers;

    assert.equal(helpers.text('  value  '), 'value');
    assert.equal(helpers.hasText('  '), false);
    assert.deepEqual(Array.from(helpers.splitLines('a\n# comment\n b ')), ['a', 'b']);
    assert.deepEqual(Array.from(helpers.unique(['a', 'a', 'b'])), ['a', 'b']);
});

test('validation helpers validate URLs, IP literals, and ports', async () => {
    const runtime = await runtimePromise;
    const helpers = runtime.window.MihomoFeatureModules.ValidationHelpers;

    assert.equal(helpers.isValidAbsoluteUrl('https://example.com/path'), true);
    assert.equal(helpers.isValidAbsoluteUrl('/relative'), false);
    assert.equal(helpers.isValidIpv4('192.168.1.1'), true);
    assert.equal(helpers.isValidIpv4('999.1.1.1'), false);
    assert.equal(helpers.isValidIpv6('2001:db8::1'), true);
    assert.equal(helpers.isIpLiteralWithOptionalPort('[2001:db8::1]:53'), true);
    assert.equal(helpers.isValidListenAddress(':7890'), true);
    assert.equal(helpers.isValidPortValue('40000-50000'), true);
    assert.equal(helpers.isValidPortListValue('40000-50000,60000/60010-60020'), true);
    assert.equal(helpers.isValidPortListValue('0-1'), false);
});

test('validation helpers collect duplicate names and describe config items', async () => {
    const runtime = await runtimePromise;
    const helpers = runtime.window.MihomoFeatureModules.ValidationHelpers;
    const issues = [];

    helpers.collectDuplicateNames(
        [{ name: 'Proxy' }, { name: 'Proxy' }, { name: 'Direct' }],
        (item) => item.name,
        (name) => `duplicate:${name}`,
        (level, message) => issues.push({ level, message })
    );

    assert.deepEqual(issues, [{ level: 'error', message: 'duplicate:Proxy' }]);
    assert.equal(helpers.describeProxy({ name: 'A' }, 0), '节点 "A"');
    assert.equal(helpers.describeRule({ logic: 'AND' }, 1), '逻辑规则 #2');
});
