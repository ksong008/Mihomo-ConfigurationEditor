#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

const rootSourceFiles = [
    'mihomo.app.js',
    'mihomo.helpers.js'
];
const sourceDirs = ['core', 'modules', 'scripts', 'tests'];
const checkExtensions = new Set(['.js', '.mjs']);

function printHelp() {
    process.stdout.write(
        [
            'Usage: node scripts/verify.mjs [--skip-offline-build]',
            '',
            'Runs syntax checks, node tests, the offline build, and git diff whitespace checks.'
        ].join('\n') + '\n'
    );
}

function parseArgs(argv) {
    const options = { skipOfflineBuild: false };
    argv.forEach((arg) => {
        if (arg === '--skip-offline-build') {
            options.skipOfflineBuild = true;
            return;
        }
        if (arg === '--help' || arg === '-h') {
            printHelp();
            process.exit(0);
        }
        throw new Error(`Unknown argument: ${arg}`);
    });
    return options;
}

async function collectSourceFiles(relativeDir) {
    const absoluteDir = path.join(repoRoot, relativeDir);
    const entries = await readdir(absoluteDir, { withFileTypes: true });
    const files = [];

    for (const entry of entries) {
        const relativePath = path.join(relativeDir, entry.name);
        if (entry.isDirectory()) {
            files.push(...await collectSourceFiles(relativePath));
            continue;
        }
        if (entry.isFile() && checkExtensions.has(path.extname(entry.name))) {
            files.push(relativePath);
        }
    }

    return files.sort();
}

function run(label, command, args) {
    process.stdout.write(`\n> ${label}\n`);
    execFileSync(command, args, {
        cwd: repoRoot,
        stdio: 'inherit'
    });
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    const sourceFiles = [
        ...rootSourceFiles,
        ...(await Promise.all(sourceDirs.map((dir) => collectSourceFiles(dir)))).flat()
    ];
    const testFiles = sourceFiles.filter((file) => file.startsWith('tests/') && file.endsWith('.test.mjs'));

    sourceFiles.forEach((file) => {
        run(`node --check ${file}`, process.execPath, ['--check', file]);
    });

    if (testFiles.length === 0) {
        throw new Error('No node:test files found under tests/');
    }
    run('node --test', process.execPath, ['--test', ...testFiles]);

    if (!options.skipOfflineBuild) {
        run('offline build', process.execPath, ['scripts/build-offline-html.mjs']);
    }

    run('git diff --check', 'git', ['diff', '--check']);
    process.stdout.write('\nVerification completed.\n');
}

main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
