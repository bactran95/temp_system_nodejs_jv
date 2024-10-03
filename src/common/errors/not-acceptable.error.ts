import { CustomError } from './custom-error';

export class NotAcceptableError extends CustomError {
	code: string;
	statusCode = 406;
	constructor(
		public message: string = 'Not Acceptable',
		public error?: string,
		code: string = 'not_acceptable',
	) {
		super(message);
		this.code = code;
		Object.setPrototypeOf(this, NotAcceptableError.prototype);
	}

	serializeErrors() {
		return [{ message: this.message }];
	}
}
