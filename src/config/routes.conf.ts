import { DemoS3Route } from '@api/routes/demo-s3.route';
import express from 'express';
import { SysRouter } from './sys.route';
import { AuthRouter } from '@api/auth/v1/auth.route';
import { UserRouter } from '@api/users/v1/user.route';
import { AdminRouter } from '@api/admin/v1/admin.route';
import { TodoRouter } from '@api/todo/v1/todo.route';
import { PaymentRouter } from '@api/payment/v1/payment.route';
import { WebhookRouter } from '@api/webhook/v1/webhook.route';

export class Routes {
	public static init(app: express.Application, router: express.Router): void {
		// user router
		new SysRouter().init(router);
		new AuthRouter().init(router);
		new TodoRouter().init(router);
		new PaymentRouter().init(router);
		new WebhookRouter().init(router);
		new DemoS3Route().init(router);
		app.use('/api', router);
	}
}
