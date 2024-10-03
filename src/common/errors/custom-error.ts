export abstract class CustomError extends Error {
	abstract statusCode: number;
	abstract code: string;
	constructor(message?: string) {
		super(message);
		// only because we are extending a built in class
		Object.setPrototypeOf(this, CustomError.prototype);
	}

	abstract serializeErrors(): {
		message: string | string[];
		field?: string;
	}[];
}
