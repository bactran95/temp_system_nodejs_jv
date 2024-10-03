import env from '@env';
import { AWSError, Endpoint, S3 } from 'aws-sdk';
import { UnableToCheckExistenceError, UnableToUploadFileError } from './errors';
import { UnableToDeleteFileError } from './errors';

export class AwsS3Service {
	private readonly s3: S3;
	private readonly bucket: string;

	constructor() {
		this.s3 = new S3({
			endpoint: new Endpoint(env.s3.endpoint),
			credentials: {
				accessKeyId: env.s3.accessKeyId,
				secretAccessKey: env.s3.secretAccessKey,
			},
			region: env.s3.region,
		});
		this.bucket = env.s3.bucket;
	}

	async uploadFile(path: string, contents: Buffer, bucket?: string): Promise<S3.ManagedUpload.SendData> {
		try {
			return await this.s3.upload({
				Bucket: bucket || this.bucket,
				Key: path,
				Body: contents,
			}).promise();
		} catch (e) {
			throw new UnableToUploadFileError(path);
		}
	}

	async deleteFile(path: string, bucket?: string): Promise<void> {
		try {
			await this.s3.deleteObject({
				Bucket: bucket || this.bucket,
				Key: path,
			}).promise();
		} catch (e) {
			throw new UnableToDeleteFileError(path);
		}
	}

	async fileExists(path: string, bucket?: string): Promise<boolean> {
		try {
			await this.s3.headObject({
				Bucket: bucket || this.bucket,
				Key: path,
			}).promise();
			return true;
		} catch (e) {
			if ((e as AWSError).code === 'NotFound') {
				return false;
			}
			throw new UnableToCheckExistenceError(path);
		}
	}

	async moveFile(source: string, destination: string, bucket?: string) {
		await this.copyFile(source, destination, bucket);
		await this.s3.deleteObject({
			Bucket: bucket || this.bucket,
			Key: source,
		}).promise();
	}

	async copyFile(source: string, destination: string, bucket?: string) {
		await this.s3.copyObject({
			Bucket: bucket || this.bucket,
			CopySource: `${bucket}/${source}`,
			Key: destination,
		}).promise();
	}

	getPublicUrl(path: string, bucket?: string) {
		return `https://${bucket || this.bucket}.s3.${this.s3.config.region}.amazonaws.com/${path}`;
	}
}
