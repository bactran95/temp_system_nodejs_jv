import { CustomError } from './custom-error';

export class TokenExpiredError extends CustomError {
	code: string;
	statusCode = 401;
	constructor(
		public message = 'Token expired',
		code: string = 'token_expired',
	) {
		super(message);
		this.code = code;
		Object.setPrototypeOf(this, TokenExpiredError.prototype);
	}

	serializeErrors() {
		return [{ message: this.message }];
	}
}
