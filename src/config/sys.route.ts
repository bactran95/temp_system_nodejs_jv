import { NextFunction, Request, Response, Router } from 'express';
import env from '@env';
export class SysRouter {
	init(router: Router) {
		const route = Router();
		route.get(
			'/ping',
			async (req: Request, res: Response, next: NextFunction) => {
				res.send(
					JSON.stringify({
						message: 'pong',
						env: env.app.name,
					}),
				);
			},
		);

		router.use('/', route);
	}
}
