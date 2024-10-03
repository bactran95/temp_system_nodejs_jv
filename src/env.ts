import * as path from 'path';
import { description, name, version } from '../package.json';

/**
 * Environment variables
 */

const env = {
	app: {
		base_url: process.env.BASE_URL || 'http://localhost:3000',
		baseImageUrl: process.env.BASE_IMAGE_URL,
		isProduction: process.env.NODE_ENV === 'production',
		isDevelopment: process.env.NODE_ENV === 'development',
		root_path: path.join(process.cwd()),
		path_file_upload: path.join(
			process.cwd(),
			process.env.UPLOAD_DIR || 'uploads',
		),
		name,
		version,
		description,
		port: Number(process.env.PORT) || 3000,
		saltRounds: process.env.SALT_ROUNDS || 10,
		cors: process.env.CORS?.split(',') || '*',
		jwtSecret: process.env['JWT_SECRET'] || '123456',
		jwtExpiredIn: process.env['JWT_EXPIRED_IN'] || '10m',
		refreshTokenSecret: process.env['REFRESH_TOKEN_SECRET'] || '1234567',
		refreshTokenExpiredIn:
			process.env['REFRESH_TOKEN_EXPIRED_IN'] || '100m',
		bodyPayloadLimit: process.env.LIMIT_PAYLOAD || '50mb',
		debugLog: process.env.DEBUG_LOG === 'true',
		cookieSecret: process.env.COOKIE_SECRET || '123456',
	},
	database: {
		mongoUri: process.env.MONGO_URI || '',
	},
	mail: {
		host: process.env.MAIL_HOST || 'smtp.javis.vn',
		port: process.env.MAIL_PORT || '587',
		user: process.env.MAIL_USER || 'prj-template@javis.vn',
		pass: process.env.MAIL_PASS || '0XzpXUB8iW',
		from: process.env.MAIL_FROM_NAME || 'prj-template@javis.vn',
	},
	lineLogin: {
		clientId: process.env.LINE_CLIENT_ID || '1660704920',
		clientSecret:
			process.env.LINE_CLIENT_SECRET ||
			'81480d88b54acbe952b187480f280e98',
		redirectUri:
			process.env.LINE_REDIRECT_URI ||
			'http://localhost:3000/api/v1/callback',
		lineLoginUrl:
			process.env.LINE_LOGIN_URL ||
			'https://access.line.me/oauth2/v2.1/authorize',
		lineOauthUrl:
			process.env.LINE_OAUTH_URL || 'https://api.line.me/oauth2/v2.1',
	},
	webapp: {
		url: process.env.WEBAPP_URL || 'http://localhost:3000',
	},
	payjp: {
		privateKey:
			process.env.PRIVATE_KEY_PAYJP || 'sk_test_ca81c7cd7c48e4752ccd681d',
		webhooKey:
			process.env.WEBHOOK_KEY_PAYJP || 'whook_aede6a8d4933652a0692decc29',
	},
	s3: {
		endpoint: process.env.AWS_END_POINT || '',
		accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
		secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
		region: process.env.AWS_REGION,
		bucket: process.env.AWS_S3_BUCKET_NAME || '',
	}
};

if (process.env.DEBUG_LOG) {
	console.log('env', env);
}

export default env;
