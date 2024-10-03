import env from '@env';
import { CustomError, RequestValidationError, isEmpty, resErr, MULTER_LIMIT_SIZE} from 'common';
import { Logger } from 'common';
import { NextFunction, Request, Response } from 'express';
import multer from 'multer';

export const errorHandler = (
	err: Error,
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	if (env.app.debugLog) {
		Logger.info(`DEBUG_LOG =======================>${err}`);
		if (!isEmpty(req.body)) {
			Logger.info('Request Body');
			Logger.debug(JSON.stringify(req.body));
		}

		console.log(err);
		Logger.error(err.message);
		Logger.debug(`Error ${err}`);
	}
	if (err instanceof CustomError) {
		const errors = err.serializeErrors().map((doc) => {
			if (Array.isArray(doc.message)) {
				doc.message.map((item) => req.__(item));
			} else {
				doc.message = req.__(doc.message);
			}
			return doc;
		});

		if (err instanceof RequestValidationError) {
			return res
				.status(err.statusCode)
				.send(resErr('error', err.code, errors));
		}

		return res
			.status(err.statusCode)
			.send(resErr(req.__(errors[0].message as string), err.code));
	}

	if (err instanceof multer.MulterError) {
		if (err.code === MULTER_LIMIT_SIZE) {
			return res
				.status(400)
				.send({ errors: [{ message: req.__('file_size_too_large') }] });
		}
	}

	if (err instanceof SyntaxError) {
		return res
			.status(400)
			.send({ errors: [{ message: req.__('some_thing_when_wrong') }] });
	}

	res.status(500).send({
		errors: [{ message: req.__('some_thing_when_wrong') }],
	});
};
