import { CustomError } from './custom-error';

export class ConflictError extends CustomError {
	code: string;
	statusCode = 409;
	constructor(
		public message: string = 'Data Conflict',
		code: string = 'data_conflict',
	) {
		super(message);
		this.code = code;
		Object.setPrototypeOf(this, ConflictError.prototype);
	}

	serializeErrors() {
		return [{ message: this.message }];
	}
}
