#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

const sourceHtmlPath = path.join(repoRoot, 'mihomo.html');
const localCssPath = path.join(repoRoot, 'mihomo.styles.css');
const defaultOutputPath = path.join(repoRoot, 'dist', 'mihomo.offline.html');

const remoteScripts = [
    {
        label: 'vue.global.prod.js',
        url: 'https://unpkg.com/vue@3.5.13/dist/vue.global.prod.js',
        tag: '<script src="https://unpkg.com/vue@3.5.13/dist/vue.global.prod.js"></script>'
    },
    {
        label: 'tailwindcss.com',
        url: 'https://cdn.tailwindcss.com/3.4.17?plugins=forms',
        tag: '<script src="https://cdn.tailwindcss.com/3.4.17?plugins=forms"></script>'
    },
    {
        label: 'js-yaml.min.js',
        url: 'https://cdnjs.cloudflare.com/ajax/libs/js-yaml/4.1.0/js-yaml.min.js',
        tag: '<script src="https://cdnjs.cloudflare.com/ajax/libs/js-yaml/4.1.0/js-yaml.min.js"></script>'
    }
];

const remoteStyle = {
    label: 'all.min.css',
    url: 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
    tag: '<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">'
};

const localScripts = [
    'mihomo.helpers.js',
    'core/state.js',
    'core/ui-runtime.js',
    'core/providers.js',
    'core/import-export.js',
    'core/persistence.js',
    'core/bootstrap.js',
    'modules/proxies.js',
    'modules/validation.js',
    'modules/dns.js',
    'modules/tproxy.js',
    'modules/rules.js',
    'modules/yaml.js',
    'mihomo.app.js'
];

function parseArgs(argv) {
    const result = { output: defaultOutputPath };
    for (let index = 0; index < argv.length; index += 1) {
        const arg = argv[index];
        if (arg === '--output' || arg === '-o') {
            const next = argv[index + 1];
            if (!next) {
                throw new Error('Missing value for --output');
            }
            result.output = path.resolve(process.cwd(), next);
            index += 1;
            continue;
        }
        if (arg === '--help' || arg === '-h') {
            printHelp();
            process.exit(0);
        }
        throw new Error(`Unknown argument: ${arg}`);
    }
    return result;
}

function printHelp() {
    process.stdout.write(
        [
            'Usage: node scripts/build-offline-html.mjs [--output <path>]',
            '',
            'Builds a fully offline single-file Mihomo editor HTML bundle.',
            `Default output: ${defaultOutputPath}`
        ].join('\n') + '\n'
    );
}

function escapeInlineScript(content) {
    return content.replace(/<\/script/gi, '<\\/script');
}

function escapeInlineStyle(content) {
    return content.replace(/<\/style/gi, '<\\/style');
}

function inlineScriptTag(label, content) {
    return `    <script>\n/* bundled: ${label} */\n${escapeInlineScript(content)}\n    </script>`;
}

function inlineStyleTag(label, content) {
    return `    <style>\n/* bundled: ${label} */\n${escapeInlineStyle(content)}\n    </style>`;
}

function replaceLiteral(source, literal, replacement) {
    if (!source.includes(literal)) {
        throw new Error(`Failed to locate expected markup: ${literal}`);
    }
    return source.replace(literal, replacement);
}

function replaceRange(source, startMarker, endMarker, replacement) {
    const start = source.indexOf(startMarker);
    if (start === -1) {
        throw new Error(`Failed to locate start marker: ${startMarker}`);
    }
    const endStart = source.indexOf(endMarker, start);
    if (endStart === -1) {
        throw new Error(`Failed to locate end marker: ${endMarker}`);
    }
    const end = endStart + endMarker.length;
    return source.slice(0, start) + replacement + source.slice(end);
}

function guessContentType(url) {
    const pathname = new URL(url).pathname.toLowerCase();
    if (pathname.endsWith('.woff2')) return 'font/woff2';
    if (pathname.endsWith('.woff')) return 'font/woff';
    if (pathname.endsWith('.ttf')) return 'font/ttf';
    if (pathname.endsWith('.otf')) return 'font/otf';
    if (pathname.endsWith('.eot')) return 'application/vnd.ms-fontobject';
    if (pathname.endsWith('.svg')) return 'image/svg+xml';
    return 'application/octet-stream';
}

async function fetchText(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Failed to download ${url}: ${response.status} ${response.statusText}`);
    }
    return response.text();
}

async function fetchDataUrl(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Failed to download asset ${url}: ${response.status} ${response.statusText}`);
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    const contentType = response.headers.get('content-type')?.split(';')[0] || guessContentType(url);
    return `data:${contentType};base64,${bytes.toString('base64')}`;
}

async function inlineCssUrls(cssText, baseUrl) {
    const urlPattern = /url\(([^)]+)\)/g;
    const assetUrls = new Map();

    for (const match of cssText.matchAll(urlPattern)) {
        const rawUrl = match[1].trim().replace(/^['"]|['"]$/g, '');
        if (!rawUrl || rawUrl.startsWith('data:') || rawUrl.startsWith('#')) continue;
        const absoluteUrl = new URL(rawUrl, baseUrl).href;
        if (!assetUrls.has(absoluteUrl)) {
            assetUrls.set(absoluteUrl, null);
        }
    }

    for (const absoluteUrl of assetUrls.keys()) {
        assetUrls.set(absoluteUrl, await fetchDataUrl(absoluteUrl));
    }

    return cssText.replace(urlPattern, (fullMatch, rawUrl) => {
        const normalized = rawUrl.trim().replace(/^['"]|['"]$/g, '');
        if (!normalized || normalized.startsWith('data:') || normalized.startsWith('#')) {
            return fullMatch;
        }
        const absoluteUrl = new URL(normalized, baseUrl).href;
        return `url("${assetUrls.get(absoluteUrl)}")`;
    });
}

function getGitRevision() {
    try {
        return execFileSync('git', ['rev-parse', '--short', 'HEAD'], {
            cwd: repoRoot,
            encoding: 'utf8'
        }).trim();
    } catch (error) {
        return 'unknown';
    }
}

async function buildOfflineHtml(outputPath) {
    let sourceHtml = await readFile(sourceHtmlPath, 'utf8');
    const localCss = await readFile(localCssPath, 'utf8');
    const bundledAt = new Date().toISOString();
    const revision = getGitRevision();

    for (const asset of remoteScripts) {
        const content = await fetchText(asset.url);
        sourceHtml = replaceLiteral(sourceHtml, asset.tag, inlineScriptTag(asset.label, content));
    }

    const fontAwesomeCss = await fetchText(remoteStyle.url);
    const inlinedFontAwesomeCss = await inlineCssUrls(fontAwesomeCss, remoteStyle.url);
    sourceHtml = replaceLiteral(sourceHtml, remoteStyle.tag, inlineStyleTag(remoteStyle.label, inlinedFontAwesomeCss));

    const localStyleStart = '<link id="mihomo-local-styles" rel="stylesheet">';
    const localStyleEnd = '</script>';
    sourceHtml = replaceRange(
        sourceHtml,
        localStyleStart,
        localStyleEnd,
        inlineStyleTag('mihomo.styles.css', localCss)
    );

    const loaderStart = sourceHtml.lastIndexOf('<script>');
    const bodyClose = sourceHtml.lastIndexOf('</body>');
    if (loaderStart === -1 || bodyClose === -1 || loaderStart > bodyClose) {
        throw new Error('Failed to locate trailing script loader block');
    }

    const banner = inlineScriptTag(
        'offline-build-meta',
        `window.__MIHOMO_OFFLINE_BUILD__ = ${JSON.stringify({
            revision,
            bundledAt,
            source: 'Test'
        }, null, 2)};`
    );

    const bundledLocalScripts = await Promise.all(
        localScripts.map(async (relativePath) => {
            const filePath = path.join(repoRoot, relativePath);
            const content = await readFile(filePath, 'utf8');
            return inlineScriptTag(relativePath, content);
        })
    );

    const inlineBundle = [banner, ...bundledLocalScripts].join('\n\n');
    sourceHtml =
        sourceHtml.slice(0, loaderStart) +
        inlineBundle +
        '\n</body>' +
        sourceHtml.slice(bodyClose + '</body>'.length);

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, sourceHtml, 'utf8');
    return { outputPath, revision, bundledAt };
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    const result = await buildOfflineHtml(options.output);
    process.stdout.write(
        `Built offline Mihomo HTML bundle\nOutput: ${result.outputPath}\nRevision: ${result.revision}\nBuilt At: ${result.bundledAt}\n`
    );
}

main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
