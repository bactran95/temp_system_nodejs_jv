import { CustomError } from './custom-error';

export class NotFoundError extends CustomError {
	code: string;
	statusCode = 404;
	constructor(message: string = 'Not found', code: string = 'not_found') {
		super(message);
		// only because we are extending a built in class
		this.code = code;
		Object.setPrototypeOf(this, NotFoundError.prototype);
	}

	serializeErrors() {
		return [{ message: this.message }];
	}
}
