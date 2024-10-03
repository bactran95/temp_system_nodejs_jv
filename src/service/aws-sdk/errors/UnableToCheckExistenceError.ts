export class UnableToCheckExistenceError extends Error {
	constructor(path: string) {
		super(`Unable to check existence for: ${path}`);
	}
}
