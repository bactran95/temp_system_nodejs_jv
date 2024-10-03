import { CustomError } from './custom-error';

export class BadRequestError extends CustomError {
	code: string;
	statusCode = 400;
	constructor(public message = 'Bad request', code: string = 'bad_request') {
		super(message);
		this.code = code;
		Object.setPrototypeOf(this, BadRequestError.prototype);
	}

	serializeErrors() {
		return [{ message: this.message }];
	}
}
