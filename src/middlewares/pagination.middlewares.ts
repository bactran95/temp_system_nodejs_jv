import { PAGE, PER_PAGE } from '@constances/constant';
import { NextFunction, Request, Response } from 'express';

export const pagination = (req: Request, res: Response, next: NextFunction) => {
	try {
		if (typeof req.query.page === 'undefined') {
			req.query.page = `${PAGE}`;
		}
		if (typeof req.query.perPage === 'undefined') {
			req.query.perPage = `${PER_PAGE}`;
		}
		return next();
	} catch (error) {
		next(error);
	}
};
