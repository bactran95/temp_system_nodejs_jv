import env from '@env';
import { PaymentRequest } from '../request/payment.request';
import Payjp from 'payjp';
const payjp = Payjp(env.payjp.privateKey);

export class PaymentController {
	async payment(signInBody: PaymentRequest) {
		const charges = await payjp.charges.create({
			amount: signInBody.amount,
			currency: 'jpy',
			card: signInBody.token,
		});
		return charges;
	}
}
