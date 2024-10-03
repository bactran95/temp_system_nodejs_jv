import { CustomError } from './custom-error';

export class ForbiddenError extends CustomError {
	code: string;
	statusCode = 403;
	constructor(
		public message: string = 'forbidden',
		code: string = 'forbidden',
	) {
		super(message);
		this.code = code;
		Object.setPrototypeOf(this, ForbiddenError.prototype);
	}

	serializeErrors() {
		return [{ message: this.message }];
	}
}
