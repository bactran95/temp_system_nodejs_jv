import { NextFunction, Request, Response, Router } from 'express';
import { WebhookController } from './webhook.controller';
import { resOK } from 'common';

export class WebhookRouter {
	private controller = new WebhookController();

	init(router: Router): void {
		const webhookRouter = Router();
		webhookRouter.use('/payjp', this.webhookPayJP.bind(this));

		router.use('/v1/webhook', webhookRouter);
	}

	private async webhookPayJP(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const rsl = await this.controller.webhookPayJP(req);
			res.status(200).json(resOK(rsl));
		} catch (error) {
			next(error);
		}
	}
}
