import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
    defaultOutputPath,
    extractLocalScriptsFromHtml,
    normalizeLocalScriptPath,
    parseArgs
} from '../scripts/build-offline-html.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

test('offline builder reads local script order from mihomo.html', async () => {
    const sourceHtml = await readFile(path.join(ROOT, 'mihomo.html'), 'utf8');
    const scripts = extractLocalScriptsFromHtml(sourceHtml);

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
        () => extractLocalScriptsFromHtml('<script>const scripts = [\'./a.js\', \'./a.js\'];</script>'),
        /Duplicate local script/
    );
    assert.throws(
        () => extractLocalScriptsFromHtml('<script>const scripts = [];</script>'),
        /empty/
    );
});

test('offline builder argument parser keeps the default output stable', () => {
    assert.equal(parseArgs([]).output, defaultOutputPath);
    assert.equal(parseArgs(['--output', '/tmp/mihomo.offline.html']).output, '/tmp/mihomo.offline.html');
    assert.throws(() => parseArgs(['--output']), /Missing value/);
    assert.throws(() => parseArgs(['--unknown']), /Unknown argument/);
});
