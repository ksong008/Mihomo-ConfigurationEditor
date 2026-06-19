import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from './support/runtime-harness.mjs';

const runtimePromise = createRuntime({
    scripts: [
        'modules/proxy-schema.js',
        'modules/proxy-node-utils.js',
        'modules/proxy-node-model.js',
        'modules/proxy-node-validation.js'
    ]
});

function createValidator(runtime, options = {}) {
    const { parseSingleProxyNode } = runtime.window.MihomoFeatureModules.ProxyNodeModel.createProxyNodeModel();
    return runtime.window.MihomoFeatureModules.ProxyNodeValidation.createProxyNodeValidation({
        parseSingleProxyNode,
        parseYamlObjectText: options.parseYamlObjectText
    });
}

test('proxy node validation reports unsupported Snell versions', async () => {
    const runtime = await runtimePromise;
    const { getProxyValidationIssues } = createValidator(runtime);
    const issues = Array.from(getProxyValidationIssues({
        name: 'snell',
        type: 'snell',
        version: '6',
        psk: 'secret'
    }));

    assert.ok(issues.some((issue) => issue.level === 'error' && issue.message.includes('Snell 的 version')));
});

test('proxy node validation handles tcp-only toggles outside TCP transports', async () => {
    const runtime = await runtimePromise;
    const { getProxyValidationIssues } = createValidator(runtime);
    const issues = Array.from(getProxyValidationIssues({
        name: 'vless-ws',
        type: 'vless',
        uuid: '00000000-0000-0000-0000-000000000000',
        network: 'ws',
        tfo: true
    }));

    assert.ok(issues.some((issue) => issue.level === 'error' && issue.message.includes('TFO 只应与 TCP')));
});

test('proxy node validation warns about unsupported xHTTP download settings', async () => {
    const runtime = await runtimePromise;
    const { getProxyValidationIssues } = createValidator(runtime, {
        parseYamlObjectText: () => ({
            path: '/download',
            extra: true,
            'reuse-settings': {
                unsupported: true
            }
        })
    });
    const issues = Array.from(getProxyValidationIssues({
        name: 'xhttp',
        type: 'vless',
        uuid: '00000000-0000-0000-0000-000000000000',
        network: 'xhttp',
        tls: true,
        _xhttpDownloadSettingsText: 'extra: true'
    }));

    assert.ok(issues.some((issue) => issue.level === 'warning' && issue.message.includes('extra')));
    assert.ok(issues.some((issue) => issue.level === 'warning' && issue.message.includes('reuse-settings.unsupported')));
});
