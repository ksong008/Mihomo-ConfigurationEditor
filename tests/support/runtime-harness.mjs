import path from 'node:path';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const defaultRuntimeScripts = [
    'mihomo.helpers.js',
    'core/state.js',
    'core/provider-group-model.js',
    'core/provider-fallback-model.js',
    'core/provider-rename-model.js',
    'modules/proxy-schema.js',
    'modules/proxy-node-utils.js',
    'modules/proxy-node-model.js',
    'modules/proxy-node-validation.js',
    'modules/proxy-node-yaml.js',
    'modules/proxies.js',
    'modules/tproxy.js',
    'modules/yaml-builders.js',
    'modules/yaml.js'
];

const dumpLikeYaml = (value) => JSON.stringify(value, null, 2);

async function loadBrowserScript(context, relativePath) {
    const source = await readFile(path.join(ROOT, relativePath), 'utf8');
    vm.runInContext(source, context, { filename: relativePath });
}

async function createRuntime(options = {}) {
    const scripts = Array.isArray(options.scripts) ? options.scripts : defaultRuntimeScripts;
    const sandbox = {
        console,
        Buffer,
        URL,
        Uint8Array,
        atob: globalThis.atob,
        btoa: globalThis.btoa,
        crypto: globalThis.crypto,
        setTimeout,
        clearTimeout,
        alert: () => {},
        navigator: {
            clipboard: {
                writeText: async () => {}
            }
        }
    };

    sandbox.window = {
        crypto: globalThis.crypto
    };
    sandbox.window.window = sandbox.window;
    sandbox.window.globalThis = sandbox;

    sandbox.jsyaml = {
        dump: dumpLikeYaml,
        load: JSON.parse
    };
    sandbox.window.jsyaml = sandbox.jsyaml;
    sandbox.globalThis = sandbox;

    const context = vm.createContext(sandbox);
    for (const script of scripts) {
        await loadBrowserScript(context, script);
    }

    return context;
}

export {
    ROOT,
    createRuntime,
    loadBrowserScript
};
