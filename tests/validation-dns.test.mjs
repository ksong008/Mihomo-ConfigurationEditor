import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'modules/validation-helpers.js',
        'modules/validation-dns.js'
    ]
});

const plain = (value) => JSON.parse(JSON.stringify(value));

function createDnsHelpers(runtime, parseYamlMapText = () => ({})) {
    return runtime.window.MihomoFeatureModules.ValidationDns.createValidationDns({
        parseYamlMapText
    });
}

test('validation dns describes supported and invalid DNS servers', async () => {
    const runtime = await runtimePromise;
    const dns = createDnsHelpers(runtime);

    assert.deepEqual(plain(dns.splitDnsServerExtras('https://dns.example/dns-query#Proxy&h3=true')), {
        base: 'https://dns.example/dns-query',
        extras: 'Proxy&h3=true'
    });

    const descriptor = plain(dns.getDnsServerDescriptor('https://dns.example/dns-query'));
    assert.equal(descriptor.valid, true);
    assert.equal(descriptor.needsBootstrap, true);
    assert.equal(descriptor.hostname, 'dns.example');

    const invalid = plain(dns.getDnsServerDescriptor('https://dns.example'));
    assert.equal(invalid.valid, false);
    assert.match(invalid.reason, /DoH/);
});

test('validation dns validates server extras and route targets', async () => {
    const runtime = await runtimePromise;
    const dns = createDnsHelpers(runtime);
    const issues = [];
    const result = dns.validateDnsServerExtras(
        'https://dns.example/dns-query#Proxy&ecs=1.1.1.1/24&skip-cert-verify=true',
        'nameserver',
        (level, message) => issues.push({ level, message }),
        { validDnsRouteTargets: new Set(['Proxy']) }
    );

    assert.deepEqual(issues, []);
    assert.deepEqual(plain(result), { usesRules: false });

    dns.validateDnsServerExtras(
        'udp://1.1.1.1#h3&skip-cert-verify=true&bad=1',
        'nameserver',
        (level, message) => issues.push({ level, message }),
        {}
    );
    assert.ok(issues.some((issue) => issue.level === 'warning' && issue.message.includes('h3')));
    assert.ok(issues.some((issue) => issue.level === 'warning' && issue.message.includes('skip-cert-verify')));
    assert.ok(issues.some((issue) => issue.level === 'error' && issue.message.includes('bad')));
});

test('validation dns validates policy maps and fake-ip rule lines', async () => {
    const runtime = await runtimePromise;
    const dns = createDnsHelpers(runtime, () => ({
        'rule-set:geo-cn': ['https://dns.example/dns-query'],
        'geosite:test': ['1.1.1.1']
    }));
    const issues = [];
    const policy = plain(dns.validateDnsPolicyMap(
        'ignored',
        'nameserver-policy',
        new Set(['geo-cn']),
        (level, message) => issues.push({ level, message }),
        { validDnsRouteTargets: new Set(['Proxy']) }
    ));

    assert.equal(policy.hasBootstrapDependency, true);
    assert.deepEqual(policy.entries, ['https://dns.example/dns-query']);
    assert.deepEqual(issues, []);

    dns.validateFakeIpRuleLines(
        ['RULE-SET,missing,fake-ip', 'MATCH,real-ip'],
        'fake-ip-filter',
        new Set(['geo-cn']),
        (level, message) => issues.push({ level, message })
    );
    assert.ok(issues.some((issue) => issue.level === 'error' && issue.message.includes('missing')));
});
