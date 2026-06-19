(function (window) {
    'use strict';

    window.MihomoCore = window.MihomoCore || {};
    window.MihomoCore.SCRIPT_MANIFEST = Object.freeze([
        './mihomo.helpers.js',
        './core/state.js',
        './core/ui-runtime.js',
        './core/provider-model.js',
        './core/providers.js',
        './core/import-export.js',
        './core/persistence.js',
        './core/bootstrap.js',
        './modules/proxy-schema.js',
        './modules/proxies.js',
        './modules/validation.js',
        './modules/dns.js',
        './modules/tproxy.js',
        './modules/rule-parser.js',
        './modules/rules.js',
        './modules/yaml-builders.js',
        './modules/yaml.js',
        './mihomo.app.js'
    ]);
})(window);
