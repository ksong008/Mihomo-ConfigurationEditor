import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { access, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import {
    extractLocalScriptManifestPathFromHtml,
    extractLocalScriptsFromManifest
} from '../scripts/build-offline-html.mjs';
import { ROOT } from './support/runtime-harness.mjs';

async function readSourceHtml() {
    return readFile(path.join(ROOT, 'mihomo.html'), 'utf8');
}

test('source html keeps one app shell and one local stylesheet loader', async () => {
    const html = await readSourceHtml();

    assert.equal((html.match(/<div id="app"/g) || []).length, 1);
    assert.equal((html.match(/id="mihomo-local-styles"/g) || []).length, 1);
    assert.equal((html.match(/<body\b/g) || []).length, 1);
    assert.equal((html.match(/<\/body>/g) || []).length, 1);
    assert.match(html, /<pre class="[^"]*"><span id="yaml-general">/);
    assert.match(html, /<script>\s*\(function \(\) \{\s*const ASSET_VERSION/);
});

test('asset version fallbacks stay in sync across source html loaders', async () => {
    const html = await readSourceHtml();
    const fallbackVersions = Array.from(html.matchAll(/\|\| '(\d+)'/g), (match) => match[1]);

    assert.ok(fallbackVersions.length >= 3);
    assert.equal(new Set(fallbackVersions).size, 1);
});

test('source html local script loader references existing files in safe order', async () => {
    const html = await readSourceHtml();
    const manifestPath = extractLocalScriptManifestPathFromHtml(html);
    const manifestSource = await readFile(path.join(ROOT, manifestPath), 'utf8');
    const scripts = extractLocalScriptsFromManifest(manifestSource);

    assert.equal(manifestPath, 'core/script-manifest.js');
    assert.equal(scripts[0], 'mihomo.helpers.js');
    assert.equal(scripts.at(-1), 'mihomo.app.js');
    assert.ok(scripts.indexOf('core/state.js') < scripts.indexOf('core/bootstrap.js'));
    assert.ok(scripts.indexOf('core/provider-model.js') < scripts.indexOf('core/providers.js'));
    assert.ok(scripts.indexOf('core/bootstrap.js') < scripts.indexOf('mihomo.app.js'));
    assert.ok(scripts.indexOf('modules/proxy-schema.js') < scripts.indexOf('modules/proxies.js'));
    assert.ok(scripts.indexOf('modules/proxy-schema.js') < scripts.indexOf('modules/proxy-node-utils.js'));
    assert.ok(scripts.indexOf('modules/proxy-node-utils.js') < scripts.indexOf('modules/proxy-node-model.js'));
    assert.ok(scripts.indexOf('modules/proxy-node-model.js') < scripts.indexOf('modules/proxy-node-validation.js'));
    assert.ok(scripts.indexOf('modules/proxy-node-validation.js') < scripts.indexOf('modules/proxy-node-yaml.js'));
    assert.ok(scripts.indexOf('modules/proxy-node-yaml.js') < scripts.indexOf('modules/proxies.js'));
    assert.ok(scripts.indexOf('modules/proxies.js') < scripts.indexOf('mihomo.app.js'));
    assert.ok(scripts.indexOf('modules/validation-helpers.js') < scripts.indexOf('modules/validation.js'));
    assert.ok(scripts.indexOf('modules/rule-parser.js') < scripts.indexOf('modules/rules.js'));
    assert.ok(scripts.indexOf('modules/yaml-builders.js') < scripts.indexOf('modules/yaml.js'));
    assert.ok(scripts.indexOf('modules/yaml.js') < scripts.indexOf('mihomo.app.js'));

    await access(path.join(ROOT, manifestPath), constants.R_OK);
    for (const script of scripts) {
        await access(path.join(ROOT, script), constants.R_OK);
    }
});
