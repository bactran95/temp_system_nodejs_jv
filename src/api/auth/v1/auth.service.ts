import { User } from '@api/users/user.model';
import env from '@env';
import { IToken, ITokenPayload } from '@interfaces/authen.interface';
import { ICreateUser, IUser } from '@interfaces/user.interface';
import jwt from 'jsonwebtoken';

export async function isExist(email: string): Promise<boolean> {
	const user = await User.findOne({ email, isVerified: true });
	return user !== null;
}

export async function createAndVerified(
	userPayload: ICreateUser,
): Promise<IUser> {
	const user = User.build({
		email: userPayload.email,
		password: userPayload.password,
	});

	await user.save();
	return user.toJSON();
}

export function getToken(
	user: ITokenPayload,
	expiresIn: string,
	secret: string,
): string {
	return jwt.sign(
		{
			id: user.id,
		},
		secret,
		{
			expiresIn,
		},
	);
}

export function decode(token: string): ITokenPayload {
	return jwt.decode(token) as unknown as ITokenPayload;
}

export function refreshToken(refreshToken: string): IToken {
	const payload: ITokenPayload = jwt.verify(
		refreshToken,
		env.app.refreshTokenSecret,
	) as ITokenPayload;
	const token = generateToken(payload);
	return token;
}

export function generateToken(payload: ITokenPayload): IToken {
	const access_token = getToken(
		{
			id: payload.id,
		},
		env.app.jwtExpiredIn,
		env.app.jwtSecret,
	);

	const newRefreshToken = getToken(
		{
			id: payload.id,
		},
		env.app.refreshTokenExpiredIn,
		env.app.refreshTokenSecret,
	);

	return {
		access_token,
		refresh_token: newRefreshToken,
	};
}
