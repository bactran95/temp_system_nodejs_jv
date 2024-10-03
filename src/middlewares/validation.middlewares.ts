import { plainToInstance } from 'class-transformer';
import { Validator, ValidatorOptions } from 'class-validator';
import * as express from 'express';
import { BadRequestError } from '@errors/bad-request-error';
import { isPlainObject } from 'lodash';
import { RequestValidationError } from 'common';

export function validateBodyReq<T>(type: T, options?: ValidatorOptions) {
	return (
		req: express.Request,
		res: express.Response,
		next: express.NextFunction,
	) => {
		try {
			validate(type, req.body, options);
			next();
		} catch (error: unknown) {
			if (error instanceof RequestValidationError) {
				next(error);
			} else {
				const message = (error as Error).message;
				next(new BadRequestError(message));
			}
		}
	};
}

export function validateParamsReq<T>(type: T) {
	return (
		req: express.Request,
		res: express.Response,
		next: express.NextFunction,
	) => {
		try {
			validate(type, req.params);
			next();
		} catch (error) {
			if (error instanceof RequestValidationError) {
				next(error);
			} else {
				const message = (error as Error).message;
				next(new BadRequestError(message));
			}
		}
	};
}

export function validateQueryReq<T>(type: T) {
	return (
		req: express.Request,
		res: express.Response,
		next: express.NextFunction,
	) => {
		try {
			validate(type, req.query);
			next();
		} catch (error) {
			if (error instanceof RequestValidationError) {
				next(error);
			} else {
				const message = (error as Error).message;
				next(new BadRequestError(message));
			}
		}
	};
}

function validate(type: any, dataValidate: any, options?: ValidatorOptions) {
	if (!isPlainObject(dataValidate)) {
		throw new BadRequestError('Data is not object');
	}
	const validator = new Validator();
	const input = plainToInstance(type, dataValidate);
	const errorsMsg = validator.validateSync(input, options || {});
	if (errorsMsg.length > 0) {
		throw new RequestValidationError(errorsMsg);
	}
	return input;
}
