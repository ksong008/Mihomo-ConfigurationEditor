import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
    assertOfflineBundle,
    defaultOutputPath,
    extractLocalScriptManifestPathFromHtml,
    extractLocalScriptsFromManifest,
    normalizeLocalScriptPath,
    parseArgs
} from '../scripts/build-offline-html.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

test('offline builder reads local script order from script manifest', async () => {
    const sourceHtml = await readFile(path.join(ROOT, 'mihomo.html'), 'utf8');
    const manifestPath = extractLocalScriptManifestPathFromHtml(sourceHtml);
    const manifestSource = await readFile(path.join(ROOT, manifestPath), 'utf8');
    const scripts = extractLocalScriptsFromManifest(manifestSource);

    assert.equal(manifestPath, 'core/script-manifest.js');
    assert.equal(scripts[0], 'mihomo.helpers.js');
    assert.equal(scripts.at(-1), 'mihomo.app.js');
    assert.equal(new Set(scripts).size, scripts.length);
    assert.ok(scripts.includes('core/bootstrap.js'));
    assert.ok(scripts.includes('modules/yaml.js'));
    assert.ok(scripts.indexOf('core/bootstrap.js') < scripts.indexOf('mihomo.app.js'));
    assert.ok(scripts.indexOf('modules/proxies.js') < scripts.indexOf('modules/yaml.js'));
});

test('offline builder rejects unsafe or duplicate local script paths', () => {
    assert.equal(normalizeLocalScriptPath('./core/state.js'), 'core/state.js');
    assert.throws(() => normalizeLocalScriptPath('../core/state.js'), /relative \.\/ path/);
    assert.throws(() => normalizeLocalScriptPath('./../core/state.js'), /Unsafe local script path/);
    assert.throws(() => normalizeLocalScriptPath('https://example.com/app.js'), /relative \.\/ path/);

    assert.throws(
        () => extractLocalScriptsFromManifest('window.MihomoCore.SCRIPT_MANIFEST = Object.freeze([\'./a.js\', \'./a.js\']);'),
        /Duplicate local script in manifest/
    );
    assert.throws(
        () => extractLocalScriptsFromManifest('window.MihomoCore.SCRIPT_MANIFEST = Object.freeze([]);'),
        /empty/
    );
    assert.throws(
        () => extractLocalScriptManifestPathFromHtml('<script>const scripts = [];</script>'),
        /manifest path/
    );
});

test('offline builder argument parser keeps the default output stable', () => {
    assert.equal(parseArgs([]).output, defaultOutputPath);
    assert.equal(parseArgs(['--output', '/tmp/mihomo.offline.html']).output, '/tmp/mihomo.offline.html');
    assert.throws(() => parseArgs(['--output']), /Missing value/);
    assert.throws(() => parseArgs(['--unknown']), /Unknown argument/);
});

test('offline builder rejects half-inlined bundles', () => {
    const validBundle = [
        '<!DOCTYPE html>',
        '<html><head>',
        '<style>body { color: #111; }</style>',
        '</head><body>',
        '<div id="app"></div>',
        '<script>window.appReady = true;</script>',
        '</body></html>'
    ].join('');

    assert.doesNotThrow(() => assertOfflineBundle(validBundle));
    assert.throws(
        () => assertOfflineBundle(validBundle.replace('</head>', '<script src="https://example.com/app.js"></script></head>')),
        /external script/
    );
    assert.throws(
        () => assertOfflineBundle(validBundle.replace('</head>', '<link rel="stylesheet" href="https://example.com/app.css"></head>')),
        /stylesheet link/
    );
    assert.throws(
        () => assertOfflineBundle(validBundle.replace('</body>', '__MIHOMO_OFFLINE_LOCAL_SCRIPTS__</body>')),
        /placeholder/
    );
});
