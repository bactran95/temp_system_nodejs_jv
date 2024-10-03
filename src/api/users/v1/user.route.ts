import { IFilterUser, IUpdateUserInterface } from '@interfaces/user.interface';
import { validateBodyReq, resOK, upload } from 'common';
import { NextFunction, Request, Response, Router } from 'express';
import { SortOrder } from 'mongoose';
import { UpdateUserRequest } from '../request/update-user.request';
import { UserController } from './user.controller';
import { verifyAdminToken } from '@middlewares/auth.middlewares';
import { CreateUserRequest } from '../request/create-user.request';

export class UserRouter {
	private controller = new UserController();

	init(router: Router): void {
		const userRouter = Router();
		userRouter.get('/', verifyAdminToken, this.getUsers.bind(this));
		userRouter.post(
			'/',
			verifyAdminToken,
			upload.single('avatar_file'),
			validateBodyReq(CreateUserRequest),
			this.createUser.bind(this),
		);
		userRouter.delete('/:id', verifyAdminToken, this.deleteUser.bind(this));
		userRouter.put(
			'/:id',
			// upload.fields([{ name: 'avatarUrl', maxCount: 1 }]),
			verifyAdminToken,
			validateBodyReq(UpdateUserRequest),
			this.updateUserProfile.bind(this),
		);
		userRouter.get(
			'/:id',
			verifyAdminToken,
			this.getUserProfileById.bind(this),
		);
		userRouter.put('/:id/lock', verifyAdminToken, this.banUser.bind(this));
		userRouter.put(
			'/:id/unlock',
			verifyAdminToken,
			this.unbanUser.bind(this),
		);
		// userRouter.put(
		// 	'/update-phone',
		// 	validateBodyReq(UpdatePhoneUserRequest),
		// 	this.updateUserPhone.bind(this),
		// );
		// userRouter.get('/reset-user', this.resetUser.bind(this));
		router.use('/v1/admin/users', userRouter);
	}

	async getUsers(req: Request, res: Response, next: NextFunction) {
		try {
			const page = Number(req.query.page) - 1 || 0;
			const limit = Number(req.query.limit) || 10;
			const sort = req.query.sort?.toString() || 'created_at';
			const order: SortOrder = (req.query.orderBy?.toString() ||
				'desc') as SortOrder;
			const filter: IFilterUser = {};
			if (req.query.email) {
				filter.email = req.query.email as string;
			}
			const users = await this.controller.getUsers(filter, {
				limit: limit,
				page: page,
				sort,
				order,
			});
			const totalPage = Math.ceil(users.total_items / limit);
			res.status(200).json(
				resOK(
					{
						users: users.items,
					},
					'Get users successfully',
					users.total_items,
					limit,
					page + 1,
					totalPage,
				),
			);
		} catch (error) {
			next(error);
		}
	}

	async getUserProfileById(req: Request, res: Response, next: NextFunction) {
		try {
			const userId = req.params.id;
			const user = await this.controller.getUserById(userId);
			res.status(200).json(resOK(user));
		} catch (error) {
			next(error);
		}
	}

	async createUser(req: Request, res: Response, next: NextFunction) {
		try {
			const dataBody = req.body;

			const user = await this.controller.createUser(dataBody);

			res.status(200).json(resOK({ user }));
		} catch (error) {
			next(error);
		}
	}

	async updateUserProfile(req: Request, res: Response, next: NextFunction) {
		try {
			const dataBody: IUpdateUserInterface = req.body;
			// const files: IImageFile = req.files as unknown as IImageFile;

			// if (files?.avatarUrl) {
			// 	// dataBody.avatarUrl = process.env.BASE_IMAGE_URL + files.avatarUrl[0].filename;
			// 	dataBody.avatarUrl =
			// 		env.app.baseImageUrl + files.avatarUrl[0].filename;
			// }
			const user = await this.controller.updateUserById(
				req.params.id?.toString(),
				dataBody,
			);

			res.status(200).json(resOK(user));
		} catch (error) {
			next(error);
		}
	}

	async deleteUser(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const user = await this.controller.deleteUser(
				req.params.id?.toString(),
			);
			res.status(200).json(resOK(user));
		} catch (error) {
			next(error);
		}
	}

	async banUser(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const user = await this.controller.updateLockUser(
				req.params.id?.toString(),
				true,
			);
			res.status(200).json(resOK(user));
		} catch (error) {
			next(error);
		}
	}

	async unbanUser(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const user = await this.controller.updateLockUser(
				req.params.id?.toString(),
				false,
			);
			res.status(200).json(resOK(user));
		} catch (error) {
			next(error);
		}
	}

	// async updateUserPhone(req: Request, res: Response, next: NextFunction) {
	// 	try {
	// 		const dataBody: IUpdateUserPhoneInterface = req.body;
	// 		await this.controller.updateUserPhoneById(
	// 			req.currentUser,
	// 			dataBody,
	// 		);

	// 		res.status(200).json({ success: true });
	// 	} catch (error) {
	// 		next(error);
	// 	}
	// }

	// async resetUser(req: Request, res: Response, next: NextFunction) {
	// 	try {
	// 		await this.controller.resetUser(req.currentUser);

	// 		res.status(200).json({ success: true });
	// 	} catch (error) {
	// 		next(error);
	// 	}
	// }
}
