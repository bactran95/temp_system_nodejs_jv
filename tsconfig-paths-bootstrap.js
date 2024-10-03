// tsconfig-paths-bootstrap.js
const tsConfigPaths = require('tsconfig-paths');

const baseUrl = './dist'; // The "outDir" specified in tsconfig.json
const cleanup = tsConfigPaths.register({
    baseUrl,
    paths: {
        '@utilities/*': ['src/utilities/*'],
        '@env': ['src/env'],
        '@config/*': ['src/config/*'],
        '@api/*': ['src/api/*'],
        '@errors/*': ['src/common/errors/*'],
        '@middlewares/*': ['src/middlewares/*'],
        '@base/*': ['src/base/*'],
        '@interfaces/*': ['src/interface/*'],
        '@constances/*': ['src/common/constances/*'],
		'@request/*': ['src/service/request/*'],
		'@line/*': ['src/service/line/*'],
    },
});
