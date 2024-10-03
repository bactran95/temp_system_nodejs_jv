import { NextFunction, Request, Response, Router } from 'express';
import { AdminController } from './admin.controller';
import { validateBodyReq, resOK } from 'common';
import { AdminSignInRequest } from '@api/auth/v1/request/signin.admin.request';

export class AdminRouter {
	private controller = new AdminController();

	init(router: Router): void {
		const adminRouter = Router();
		adminRouter.post(
			'/login',
			validateBodyReq(AdminSignInRequest),
			this.signIn.bind(this),
		);

		router.use('/v1/admin', adminRouter);
	}

	private async signIn(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const bodyParams = {
				email: req.body.email,
				password: req.body.password,
			};
			const token = await this.controller.signIn(bodyParams);
			// res.status(200).json({ token });
			res.status(200).json(resOK({ access_token: token }));
		} catch (error) {
			next(error);
		}
	}
}
