import multer from 'multer';
import env from '@env';

const whitelist = [
	'video/mp4',
	'image/png',
	'image/jpg',
	'image/gif',
	'image/svg+xml',
	'image/jpeg',
	'application/pdf',
	'application/postscript',
];

const storage = multer.diskStorage({
	destination: function (request, file, callback) {
		callback(null, `${env.app.path_file_upload}/`);
	},
	filename: function (request, file, callback) {
		// const [filename, ] = (request.url as string).split('/');
		const [filename, fileExtension] = file.originalname.split('.');

		callback(null, filename + '-' + Date.now() + '.' + fileExtension);
	},
});

export const upload = multer({
	storage: storage,
	limits: {
		fileSize: 104857600,
	},
	fileFilter: function (_req, file, cb) {
		if (!whitelist.includes(file.mimetype)) {
			return cb(new Error('file_is_not_allowed'));
		}

		cb(null, true);
	},
});

export function filename(file: Express.Multer.File) {
	const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
	return (
		uniqueSuffix + '.' + getCorrectEncoding(file.originalname).split('.').pop()
	);
}

// fix issue https://github.com/expressjs/multer/issues/1104
export function getCorrectEncoding(str: string) {
	return Buffer.from(str, 'latin1').toString('utf-8');
}

const memoryStorage = multer.memoryStorage();

export const uploadWithMemoryStorage = multer({
	storage: memoryStorage,
	limits: {
		fileSize: 104857600,
	},
	fileFilter: function (_req, file, cb) {
		if (!whitelist.includes(file.mimetype)) {
			return cb(new Error('file_is_not_allowed'));
		}

		cb(null, true);
	},
});
