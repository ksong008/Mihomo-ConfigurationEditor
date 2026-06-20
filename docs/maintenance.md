# Maintenance

This project is a static Vue application. Keep changes small, testable, and compatible with direct browser usage of `mihomo.html`.

## Source Layout

- `mihomo.html` owns the page shell and Vue template.
- `mihomo.styles.css` owns local styles loaded by the source page and inlined into offline builds.
- `mihomo.helpers.js` contains shared browser helpers used by `core/` and `modules/`.
- `core/script-manifest.js` is the single source of truth for browser script load order.
- `core/provider-model.js` contains provider and rule-provider state constructors plus provider URL helpers.
- `core/provider-group-model.js` contains proxy group member candidate, ordering, and pruning helpers.
- `core/provider-fallback-model.js` contains provider payload fallback snapshot and preview helpers.
- `core/provider-rename-model.js` contains provider, proxy, and group rename propagation helpers.
- `core/provider-group-editor.js` contains proxy-group editing flows, ordering, collapse state, and region group injection.
- `core/provider-subscription-editor.js` contains provider list editing, chain sync, fallback preview, and rename propagation wiring.
- `core/rule-provider-editor.js` contains rule-provider list editing, ordering, and rename propagation.
- `core/import-model.js` contains import normalization helpers used by import/export workflows.
- `core/bootstrap-ui.js` contains crash/cache UI state and bilingual label DOM layout wiring.
- `core/listener-editor.js` contains listener editor state helpers for users, tunnel network, and Shadowsocks password UX.
- `core/` contains state, bootstrap, persistence, import/export, provider, and UI runtime modules.
- `modules/proxy-schema.js` contains proxy capability matrices and static protocol option sets.
- `modules/proxy-node-utils.js` contains proxy node text parsing, normalization, and YAML compaction helpers.
- `modules/proxy-node-model.js` contains proxy node import/default state normalization.
- `modules/proxy-node-validation.js` contains proxy node validation issue generation.
- `modules/proxy-node-yaml.js` contains proxy node YAML export sanitization.
- `modules/validation-helpers.js` contains shared validation utility functions.
- `modules/validation-dns.js` contains DNS server, DNS policy, and fake-ip filter validation helpers.
- `modules/validation-listeners.js` contains listener-specific runtime validation.
- `modules/validation-providers.js` contains provider and rule-provider runtime validation.
- `modules/validation-groups-rules.js` contains proxy-group and rule runtime validation.
- `modules/tproxy-builders.js` contains routing, nftables, systemd, and install script generators.
- `modules/rule-parser.js` contains rule string parsing and rule condition display helpers.
- `modules/yaml-builders.js` contains shared YAML build helpers and listener sanitizers.
- `modules/` contains feature modules for proxies, validation, DNS, rules, TProxy, and YAML generation.
- `scripts/build-offline-html.mjs` builds `dist/mihomo.offline.html` by reading the script order from `core/script-manifest.js`.
- `tests/support/runtime-harness.mjs` provides the browser-like VM runtime used by Node tests.

## Local Verification

Run the full verification before publishing or changing config generation logic:

```bash
node scripts/verify.mjs
```

This runs:

- JavaScript syntax checks for source, scripts, and tests.
- Node smoke tests.
- Offline HTML build.
- `git diff --check`.

For a faster local pass that does not download CDN assets:

```bash
node scripts/verify.mjs --skip-offline-build
```

## Updating Mihomo Compatibility

When aligning with upstream `MetaCubeX/mihomo` changes:

1. Prefer the upstream `Meta` branch source and `docs/config.yaml` over wiki pages when they disagree.
2. Keep import, UI state, validation, YAML export, and tests in the same change batch.
3. Preserve unknown or protocol-specific fields when the editor cannot safely model them.
4. Add fixture coverage for import paths and smoke coverage for YAML export paths.
5. Rebuild the offline file with `node scripts/build-offline-html.mjs` before handing a local build to users.

## Commit Batches

Use focused local commits:

- Feature compatibility updates.
- Test or fixture coverage.
- Build and verification tooling.
- Documentation or maintenance process updates.

Avoid mixing large template restructuring with protocol behavior changes unless the test coverage already proves both paths.
