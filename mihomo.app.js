(function (window) {
    'use strict';

    if (!window.MihomoCore || typeof window.MihomoCore.bootstrapApp !== 'function') {
        throw new Error('bootstrap 未加载，请确认先引入 ./core/bootstrap.js');
    }

    window.MihomoCore.bootstrapApp();
})(window);
