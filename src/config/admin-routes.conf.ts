import { AdminRouter } from '@api/admin/v1/admin.route';
import { TodoRouter } from '@api/todo/v1/todo.route';
import { UserRouter } from '@api/users/v1/user.route';
import express from 'express';

export class AdminRoutes {
	public static init(app: express.Application, router: express.Router): void {
		new AdminRouter().init(router);
		new UserRouter().init(router);
		app.use('/api', router);
	}
}
