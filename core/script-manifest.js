(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.SCRIPT_MANIFEST = Object.freeze([
        './mihomo.helpers.js',
        './core/state.js',
        './core/ui-runtime.js',
        './core/provider-model.js',
        './core/provider-group-model.js',
        './core/provider-fallback-model.js',
        './core/provider-rename-model.js',
        './core/provider-group-editor.js',
        './core/provider-subscription-editor.js',
        './core/rule-provider-editor.js',
        './core/providers.js',
        './core/import-model.js',
        './core/import-export.js',
        './core/persistence.js',
        './core/bootstrap-ui.js',
        './core/listener-editor.js',
        './core/bootstrap.js',
        './modules/proxy-schema.js',
        './modules/proxy-node-utils.js',
        './modules/proxy-node-model.js',
        './modules/proxy-node-validation.js',
        './modules/proxy-node-yaml.js',
        './modules/proxies.js',
        './modules/validation-helpers.js',
        './modules/validation-dns.js',
        './modules/validation-listeners.js',
        './modules/validation-providers.js',
        './modules/validation-groups-rules.js',
        './modules/validation.js',
        './modules/dns.js',
        './modules/tproxy-builders.js',
        './modules/tproxy.js',
        './modules/rule-parser.js',
        './modules/rules.js',
        './modules/yaml-builders.js',
        './modules/yaml.js',
        './mihomo.app.js'
    ]);
})(window);
