import env from '@env';
import { Request } from 'express';
import { BadRequestError } from '@errors/bad-request-error';

export class WebhookController {
	async webhookPayJP(req: Request) {
		const signature = req.headers['payjp-signature'];
		if (req.headers['x-payjp-webhook-token'] != env.payjp.webhooKey) {
			throw new BadRequestError('Invalid token');
		}
		const body = req.body;
		console.log(req.body.type, 'req.body.type');
		return body;
	}
}
