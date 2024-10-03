import { ValidationError } from 'class-validator';
import { CustomError } from './custom-error';

export class RequestValidationError extends CustomError {
	code: string;
	statusCode = 400;

	constructor(
		private errors: ValidationError[],
		code: string = 'invalid_request_parameters',
	) {
		super('Invalid request parameters');
		this.code = code;
		// only because we are extending a built in class
		Object.setPrototypeOf(this, RequestValidationError.prototype);
	}

	serializeErrors() {
		return this.errors.map((err: ValidationError) => {
			const errorMessage = err.constraints
				? Object.values(err.constraints)[0]
				: 'some_thing_when_wrong';

			return { message: errorMessage, field: err.property };
		});
	}
}
