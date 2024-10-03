import { CustomError } from './custom-error';

export class NotAuthorizedError extends CustomError {
	code: string;
	statusCode = 401;
	// reason = 'not authorized';
	constructor(
		public reason: string = 'not authorized',
		code: string = 'not_authorized',
	) {
		super(reason);
		// only because we are extending a built in class
		this.code = code;
		Object.setPrototypeOf(this, NotAuthorizedError.prototype);
	}

	serializeErrors() {
		return [{ message: this.reason }];
	}
}
