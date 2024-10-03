// @ts-check

const eslint = require('@eslint/js');
const tseslint = require('typescript-eslint');

module.exports = tseslint.config(
	eslint.configs.recommended,
	...tseslint.configs.recommended,
	{
		// rules: {
		// 	'@typescript-eslint/naming-convention': [
		// 		'error',
		// 		{
		// 			selector: ['variable', 'function'],
		// 			format: ['camelCase'],
		// 			leadingUnderscore: 'allow',
		// 		}
		// 	]
		// },
		ignores: ['dist/*', 'tsconfig-paths-bootstrap.js'],
	}
);
