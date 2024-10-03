export class UnableToDeleteFileError extends Error {
	constructor(location: string) {
		super(`Unable to delete file located at: ${location}`);
	}
}
