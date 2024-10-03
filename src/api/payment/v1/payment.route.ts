import { NextFunction, Request, Response, Router } from 'express';
import { PaymentController } from './payment.controller';
import { validateBodyReq, resOK } from 'common';
import { PaymentRequest } from '@api/payment/request/payment.request';

export class PaymentRouter {
	private controller = new PaymentController();

	init(router: Router): void {
		const paymentRouter = Router();
		paymentRouter.post(
			'/',
			validateBodyReq(PaymentRequest),
			this.payment.bind(this),
		);

		router.use('/v1/payment', paymentRouter);
	}

	private async payment(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const bodyParams = {
				token: req.body.token,
				amount: req.body.amount,
			};
			const rsl = await this.controller.payment(bodyParams);
			res.status(200).json(resOK(rsl));
		} catch (error) {
			next(error);
		}
	}
}
