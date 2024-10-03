import { Admin } from '@api/admin/admin.model';
import { User } from '@api/users/user.model';
import env from '@env';
import {
	BadRequestError,
	TokenExpiredError,
	TokenInvalidError,
	NotAuthorizedError,
	ForbiddenError,
} from 'common';
import { ITokenPayload } from '@interfaces/authen.interface';
import axios from 'axios';
import { NextFunction, Request, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

export const verifyToken = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const { authorization } = req.headers;
		if (authorization) {
			let data = null;
			const tokenWithoutBearer = authorization.replace('Bearer ', '');
			data = jwt.verify(tokenWithoutBearer, env.app.jwtSecret);
			const payload = data as JwtPayload;
			const user = await User.findById(payload.id);
			if (!user || user.locked) {
				throw new NotAuthorizedError('unauthorized');
			}
			req.currentUser = user as any;
			return next();
		} else {
			if (req.headers['access-token'] == null) {
				throw new ForbiddenError('access-token is missing');
			}

			const isVerified = await verifyId(
				req.headers['access-token'] as string,
			);
			if (!isVerified) {
				next(new ForbiddenError('access-token is not verified'));
			}

			const memberLine = await getProfile(
				req.headers['access-token'] as string,
			);
			if (!memberLine) {
				next(new BadRequestError('profile not found'));
			}

			let member = await User.findOne({
				lineUserId: memberLine.userId,
			});
			if (!member) {
				const newMember = await User.create({
					lineUserId: memberLine.userId,
					avatarUrl: memberLine.pictureUrl,
					first_name: memberLine.displayName,
				});
				member = newMember;
			}
			req.currentUser = member?.toJSON() as any;
			next();
		}
	} catch (e) {
		if (e instanceof jwt.TokenExpiredError) {
			next(new TokenExpiredError('token_expired'));
		} else if (e instanceof jwt.JsonWebTokenError) {
			next(new TokenInvalidError('token_invalid'));
		} else {
			next(e);
		}
	}
};

const verifyId = async (token: string) => {
	try {
		const oauth2 = await axios(
			`https://api.line.me/oauth2/v2.1/verify?access_token=${token}`,
			{
				method: 'GET',
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: 'application/json',
				},
			},
		);
		if (!oauth2.data) {
			throw new BadRequestError('Invalid token');
		}
		if (oauth2.data?.client_id != process.env.LIFF_CHANNEL_ID) {
			throw new BadRequestError(
				`client_id mismatch ${oauth2.data?.client_id} != ${process.env.LIFF_CHANNEL_ID}`,
			);
		}
		if (oauth2.data?.expires_in <= 0) {
			throw new BadRequestError(`expired ${oauth2.data?.expires_in} < 0`);
		}
		return true;
	} catch (error: unknown) {
		const message =
			((error as any)?.response.data.error_description as string) ||
			(error as Error).message ||
			(error as string);
		throw new BadRequestError(message);
	}
};

const getProfile = async (token: string): Promise<any | null> => {
	try {
		const profile = await axios('https://api.line.me/v2/profile', {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${token}`,
				Accept: 'application/json',
			},
		});
		if (!profile.data) {
			throw new BadRequestError('Invalid token');
		}
		return profile?.data as Promise<any>;
	} catch (error: unknown) {
		const message =
			((error as any)?.response.data.error_description as string) ||
			(error as Error).message ||
			(error as string);
		throw new BadRequestError(message);
	}
};

export const verifyAdminToken = async (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	try {
		const { authorization } = req.headers;
		if (authorization) {
			let data = null;
			const tokenWithoutBearer = authorization.replace('Bearer ', '');
			data = jwt.verify(tokenWithoutBearer, env.app.jwtSecret);
			const payload = data as JwtPayload;
			const admin = await Admin.findById(payload.id);
			if (!admin) {
				throw new NotAuthorizedError('unauthorized');
			}
			req.currentUser = admin as any;
			return next();
		}
		next(new NotAuthorizedError('unauthorized'));
	} catch (e) {
		console.log(e);
		if (e instanceof jwt.TokenExpiredError) {
			next(new TokenExpiredError('token_expired'));
		} else if (e instanceof jwt.JsonWebTokenError) {
			next(new TokenInvalidError('token_invalid'));
		} else {
			next(e);
		}
	}
};
