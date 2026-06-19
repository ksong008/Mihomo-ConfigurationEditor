import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'mihomo.helpers.js',
        'modules/rule-parser.js'
    ]
});

const plain = (value) => JSON.parse(JSON.stringify(value));

test('rule parser handles simple and match rules', async () => {
    const runtime = await runtimePromise;
    const { parseRuleString } = runtime.window.MihomoFeatureModules.RuleParser;

    assert.deepEqual(plain(parseRuleString('DOMAIN-SUFFIX,example.com,Proxy')), {
        type: 'DOMAIN-SUFFIX',
        value: 'example.com',
        not: false,
        noResolve: false,
        src: '',
        target: 'Proxy'
    });
    assert.deepEqual(plain(parseRuleString('MATCH,DIRECT')), {
        type: 'MATCH',
        value: '',
        target: 'DIRECT',
        noResolve: false,
        not: false,
        src: ''
    });
});

test('rule parser preserves not, src, and no-resolve metadata', async () => {
    const runtime = await runtimePromise;
    const { parseRuleString } = runtime.window.MihomoFeatureModules.RuleParser;

    assert.deepEqual(plain(parseRuleString('NOT,((IP-CIDR,10.0.0.0/8,no-resolve,src,lan)),PASS-RULE')), {
        type: 'IP-CIDR',
        value: '10.0.0.0/8',
        not: true,
        noResolve: true,
        src: 'lan',
        target: 'PASS-RULE'
    });
});

test('rule parser handles logical rules and display formatting', async () => {
    const runtime = await runtimePromise;
    const { formatConditions, parseRuleString } = runtime.window.MihomoFeatureModules.RuleParser;
    const parsed = plain(parseRuleString('AND,((DOMAIN-SUFFIX,example.com),(NOT,((GEOIP,CN,no-resolve)))),Proxy'));

    assert.equal(parsed.logic, 'AND');
    assert.equal(parsed.not, false);
    assert.equal(parsed.target, 'Proxy');
    assert.deepEqual(parsed.conditions, [
        { type: 'DOMAIN-SUFFIX', value: 'example.com', not: false, noResolve: false, src: '' },
        { type: 'GEOIP', value: 'CN', not: true, noResolve: true, src: '' }
    ]);
    assert.equal(formatConditions(parsed), 'DOMAIN-SUFFIX,example.com && NOT GEOIP,CN');
});
