import { AUTH_STATE } from '@constances/constant';
import env from '@env';
import {
	ISignInInterface,
	ISignUpInterface,
} from '@interfaces/authen.interface';

import { verifyAdminToken, verifyToken } from '@middlewares/auth.middlewares';
import { validateBodyReq } from '@middlewares/validation.middlewares';
import {
	NotAcceptableError,
	TokenExpiredError,
	TokenInvalidError,
	resOK
} from 'common';
import crypto from 'crypto';
import { NextFunction, Request, Response, Router } from 'express';
import jwt from 'jsonwebtoken';
import { AuthController } from './auth.controller';
import { LoginRequest } from './request/login.request';
import { RefreshTokenRequest } from './request/refresh-token.request';
import { RegisterRequest } from './request/signup.request';
export class AuthRouter {
	private controller = new AuthController();

	public init(router: Router): void {
		const authRouter = Router();
		authRouter
			.get('/me', verifyToken, this.getMe.bind(this))
			.get('/admin/me', verifyAdminToken, this.getMeAdmin.bind(this))
			.get('/login_by_line', this.loginByLine.bind(this))
			.get('/callback', this.callback.bind(this))
			.post(
				'/login',
				validateBodyReq(LoginRequest),
				this.signIn.bind(this),
			)
			.post(
				'/register',
				validateBodyReq(RegisterRequest),
				this.signUp.bind(this),
			)
			.post('/reset_password', this.requestResetPassword.bind(this))
			.put('/update_password', this.updatePassword.bind(this))
			.post(
				'/refresh_token',
				validateBodyReq(RefreshTokenRequest),
				this.refreshToken.bind(this),
			)
			.post('/verify_token', this.verifyToken.bind(this));
		router.use('/v1', authRouter);
	}

	private async loginByLine(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const state = crypto.randomBytes(8).toString('hex');
			res.cookie(AUTH_STATE, state, {
				httpOnly: true,
				secure: env.app.isProduction ? true : false, // Set to true if using HTTPS, necessary for SameSite=None
				sameSite: 'lax', // Use 'None' for cross-site cookie use
				maxAge: 300000, // Max age in milliseconds
				path: '/',
				signed: true,
			});

			const url = `${
				env.lineLogin.lineLoginUrl
			}?response_type=code&client_id=${
				env.lineLogin.clientId
			}&redirect_uri=${encodeURIComponent(
				env.lineLogin.redirectUri,
			)}&state=${state}&scope=openid%20profile%20email`;
			res.status(200).json(resOK({ url }));
		} catch (error) {
			next(error);
		}
	}

	private async callback(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			if (
				!req.query.code ||
				!req.query.state ||
				!req.signedCookies[AUTH_STATE]
			) {
				return next(
					new NotAcceptableError(
						'invalid request.',
						'invalid_request.',
					),
				);
			}
			const code = req.query?.code?.toString() || '';
			const callbackState = req.query.state?.toString() || '';
			const cookieState = req.signedCookies[AUTH_STATE];
			const token = await this.controller.handleLineLogin(code, callbackState, cookieState);
			const url = `${env.webapp.url}/line_login?token=${token}`;
			res.redirect(url);
		} catch (error) {
			next(error);
		}
	}

	private async refreshToken(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const token = await this.controller.refreshToken(
				req.body.refresh_token,
			);
			res.status(200).json(resOK(token));
		} catch (error) {
			if (error instanceof jwt.TokenExpiredError) {
				next(new TokenExpiredError('token_expired'));
			} else if (error instanceof jwt.JsonWebTokenError) {
				next(new TokenInvalidError('token_invalid'));
			} else {
				next(error);
			}
		}
	}

	private async signIn(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const bodyParams: ISignInInterface = {
				email: req.body.email,
				password: req.body.password,
			};
			const token = await this.controller.signIn(bodyParams);
			res.status(200).json(resOK(token));
		} catch (error) {
			next(error);
		}
	}

	private async getMe(req: Request, res: Response, next: NextFunction) {
		try {
			const user = await this.controller.getMe(req.currentUser.id);
			res.status(200).json(resOK(user));
		} catch (error) {
			next(error);
		}
	}

	private async getMeAdmin(req: Request, res: Response, next: NextFunction) {
		try {
			const admin = await this.controller.getMeAdmin(req.currentUser.id);
			res.status(200).json(resOK(admin));
		} catch (error) {
			next(error);
		}
	}

	private async signUp(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { password, email, first_name, last_name, phone_number } = req.body;
			const bodyParams: ISignUpInterface = {
				password,
				email,
				first_name,
				last_name,
				phone_number,
			};
			const user = await this.controller.signUp(bodyParams);
			res.status(200).json(resOK({ ...user }));
		} catch (error) {
			next(error);
		}
	}

	private async requestResetPassword(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { email } = req.body;
			await this.controller.requestResetPassword(email);

			res.status(200).json(
				resOK({}, 'Request reset password successfully'),
			);
		} catch (error) {
			next(error);
		}
	}

	private async updatePassword(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { token, password } = req.body;

			await this.controller.updatePassword(token, password);

			res.status(200).json(
				resOK({}, 'Request reset password successfully'),
			);
		} catch (error) {
			next(error);
		}
	}

	private async verifyToken(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { email, token } = req.body;
			const result = await this.controller.verifyToken(email, token);
			res.status(200).json(resOK(result));
		} catch (error) {
			next(error);
		}
	}
}
