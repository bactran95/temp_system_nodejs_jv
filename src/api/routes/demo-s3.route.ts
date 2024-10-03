import { filename, uploadWithMemoryStorage } from '@utilities/media.util';
import { BadRequestError, resOK } from 'common';
import { NextFunction, Request, Response, Router } from 'express';
import { AwsS3Service } from '../../service/aws-sdk/aws-s3.service';

export class DemoS3Route {
	private readonly awsS3Service = new AwsS3Service();

	init(router: Router): void {
		const subRouter = Router();
		subRouter.post('/upload-file', uploadWithMemoryStorage.single('files'), this.uploadFile.bind(this));
		subRouter.post('/delete-file', this.deleteFile.bind(this));
		subRouter.post('/file-exists', this.fileExists.bind(this));
		router.use('/v1/demo-s3', subRouter);
	}

	async uploadFile(req: Request, res: Response, next: NextFunction) {
		try {
			if (!req.file) {
				throw new BadRequestError('file_is_required');
			}
			const path = filename(req.file);
			const result = await this.awsS3Service.uploadFile(path, req.file.buffer);

			res.status(200).json(resOK({
				ok: true,
				publicUrl: this.awsS3Service.getPublicUrl(path),
				result,
			}));
		} catch (error) {
			next(error);
		}
	}

	async deleteFile(req: Request, res: Response, next: NextFunction) {
		try {
			const filePath = req.body.filePath;
			if (typeof filePath !== 'string') {
				throw new BadRequestError('file_path_is_required');
			}
			const result = await this.awsS3Service.deleteFile(filePath);
			res.status(200).json(resOK({
				ok: true,
				result,
			}));
		} catch (err) {
			next(err);
		}
	}

	async fileExists(req: Request, res: Response, next: NextFunction) {
		try {
			const filePath = req.body.filePath;
			if (typeof filePath !== 'string') {
				throw new BadRequestError('file_path_is_required');
			}
			const result = await this.awsS3Service.fileExists(filePath);
			res.status(200).json(resOK({
				ok: true,
				result,
			}));
		} catch (err) {
			next(err);
		}
	}
}
