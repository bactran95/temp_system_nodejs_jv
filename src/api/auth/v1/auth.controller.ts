import { Admin } from '@api/admin/admin.model';
import { Token } from '@api/tokens/token.model';
import { User } from '@api/users/user.model';
import { BadRequestError, NotAuthorizedError, NotFoundError } from 'common';
import {
	ISignInInterface,
	ISignUpInterface,
	IToken,
} from '@interfaces/authen.interface';
import { ICreateUserWithLine, IUser } from '@interfaces/user.interface';
import { EncUtil } from 'common';
import { sendMail } from '@utilities/mail.util';
import * as otp from 'otp-generator';
import * as AuthService from './auth.service';
import * as UserService from '@api/users/v1/user.service';
import { LineLogin } from '@line/index';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { resetPassword } from '../../../mail-templates/reset-password.template';
import env from '@env';
export class AuthController {
	async handleLineLogin(
		code: string,
		callbackState: string,
		cookieState: string,
	): Promise<IToken> {
		if (cookieState !== callbackState) {
			throw new NotAuthorizedError(
				'validation failed.',
				'validation_failed.',
			);
		}

		const data = await LineLogin.getAccesTokenFromLine(code);
		const userProfile: JwtPayload | string | null = jwt.decode(
			data.id_token,
		);

		if (!userProfile || typeof userProfile === 'string') {
			throw new NotAuthorizedError(
				'invalid id_token.',
				'invalid_id_token.',
			);
		}

		const user = await this.findUserByEmailAndCreate({
			email: userProfile.email,
			name: userProfile.name,
			picture: userProfile.picture,
			user_line_id: userProfile.sub?.toString() || '',
		});

		const token = AuthService.generateToken({
			id: user.id,
		});

		return {
			access_token: token.access_token,
			refresh_token: token.refresh_token,
		};
	}
	async signIn(signInBody: ISignInInterface): Promise<IToken> {
		const existingUser = await User.findOne({
			email: signInBody.email,
		});
		if (existingUser === null || existingUser.locked) {
			throw new NotFoundError('email_not_found');
		}

		const isValidPassword = await EncUtil.comparePassword(
			signInBody.password,
			existingUser.password!,
		);

		if (!isValidPassword) {
			throw new BadRequestError('the_password_is_in_correct');
		}

		const token = AuthService.generateToken({
			id: existingUser.id,
		});

		return {
			access_token: token.access_token,
			refresh_token: token.refresh_token,
		};
	}

	async signUp(signUpBody: ISignUpInterface): Promise<IUser> {
		const existingUser = await User.findOne({
			email: signUpBody.email,
		});
		if (existingUser) {
			throw new BadRequestError('email_already_exists');
		}

		const user = await AuthService.createAndVerified({
			...signUpBody,
			password: await EncUtil.createHash(signUpBody.password),
		});
		return user;
	}

	async getMe(_id: string): Promise<IUser | null> {
		return await User.findOne({ _id });
	}

	async getMeAdmin(_id: string): Promise<IUser | null> {
		return await Admin.findOne({ _id });
	}

	async requestResetPassword(email: string): Promise<void> {
		const existingUser = await User.findOne({ email });
		if (existingUser === null || existingUser.locked) {
			throw new NotFoundError('email_not_found');
		}

		let newToken = await Token.findOne({ userId: existingUser._id });
		if (!newToken) {
			newToken = await new Token({
				userId: existingUser._id,
				token: otp.generate(6, {
					digits: true,
					lowerCaseAlphabets: false,
					upperCaseAlphabets: false,
					specialChars: false,
				}),
			}).save();
		}

		console.log('existingUser', existingUser);

		sendMail(
			existingUser.email,
			'Password reset: ',
			newToken.token,
			resetPassword(
				existingUser.first_name + ' ' + existingUser.last_name,
				`${env.webapp.url}/reset_password?token=${newToken.token}`,
			),
		);
	}

	async verifyToken(email: string, token: string): Promise<boolean> {
		const user = await User.findOne({ email });
		if (user === null || user.locked) {
			throw new NotFoundError('User not found');
		}

		const existingToken = await Token.exists({
			userId: user.id,
			token: token,
		});

		if (existingToken === null) {
			throw new BadRequestError('Invalid OTP or expired');
		}

		return true;
	}

	async updatePassword(token: string, newPassword: string): Promise<void> {
		const existingToken = await Token.findOne({
			token: token,
		});
		if (existingToken === null) {
			throw new BadRequestError('Invalid OTP or expired');
		}

		await User.updateOne(
			{ _id: existingToken.user_id },
			{
				password: await EncUtil.createHash(newPassword),
			},
		);
	}

	// async resetPassword(token: string, newPassword: string): Promise<void> {
		// const existingUser = await User.findOne({ email });
		// if (existingUser === null || existingUser.locked) {
		// 	throw new NotFoundError('User not found');
		// }
		// const existingToken = await Token.findOne({
		// 	userId: existingUser._id,
		// 	token: token,
		// });
		// console.log('existingToken', existingToken);
		// if (existingToken === null) {
		// 	throw new BadRequestError('Invalid OTP or expired');
		// }
		// await User.updateOne(
		// 	{ _id: existingUser._id },
		// 	{
		// 		password: await EncUtil.createHash(newPassword),
		// 	},
		// );
		// await Token.deleteOne({ _id: existingToken._id });
	// }

	async refreshToken(refreshToken: string): Promise<IToken> {
		const payload = AuthService.decode(refreshToken);
		if (!payload || !payload.id) {
			throw new NotAuthorizedError('unauthorized');
		}

		const user = await User.findOne({ _id: payload.id });
		if (!user || user.locked) {
			throw new NotAuthorizedError('unauthorized');
		}
		const tokens = AuthService.refreshToken(refreshToken);
		return {
			access_token: tokens.access_token,
			refresh_token: tokens.refresh_token,
		};
	}

	async findUserByEmailAndCreate(
		dataBody: ICreateUserWithLine,
	): Promise<IUser> {
		const user = await UserService.findUserByEmailAndCreate(dataBody);
		return user;
	}
}
