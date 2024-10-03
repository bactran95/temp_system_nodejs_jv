export class UnableToUploadFileError extends Error {
	constructor(location: string) {
		super(`Unable to write file at location: ${location}`);
	}
}
