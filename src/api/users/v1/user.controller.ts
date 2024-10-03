import { BadRequestError, EncUtil, buildQuery } from 'common';
import { IFilterPaging } from '@interfaces/Base.interface';
import { IPagination } from '@interfaces/IPagination';
import {
	ICreateUser,
	IFilterUser,
	IUpdateUserInterface,
	IUser,
} from '@interfaces/user.interface';
import { User } from '../user.model';
import * as UserService from './user.service';
export class UserController {
	async createUser(dataBody: ICreateUser): Promise<IUser> {
		const existingUser = await User.findOne({
			email: dataBody.email,
		});
		if (existingUser) {
			throw new BadRequestError('email_already_exists');
		}

		return UserService.createUser({
			...dataBody,
			password: await EncUtil.createHash(dataBody.password),
		});
	}

	async getUsers(
		filter: IFilterUser,
		paging: IFilterPaging,
	): Promise<IPagination<IUser>> {
		const query = buildQuery(filter);
		const total_items = await User.countDocuments(query);
		const user = await User.find(query)
			.skip(paging.page * paging.limit)
			.limit(paging.limit)
			.sort({ [paging.sort]: paging.order })
			.exec();
		return {
			total_items,
			items: user.map((x) => x.toJSON()) as IUser[],
		};
	}

	async getUserById(_id: string): Promise<IUser | null> {
		return UserService.getUserById(_id);
	}

	async updateUserById(
		id: string,
		dataBody: IUpdateUserInterface,
	): Promise<any> {
		const user = await UserService.getUserById(id);
		if (!user) {
			throw new BadRequestError('account_not_found');
		}
		// if (user.email != dataBody.email) {
		// 	const checkUserName = await UserService.findOneWithCondition({
		// 		email: dataBody.email,
		// 	});
		// 	if (checkUserName) {
		// 		throw new BadRequestError('email_already_exists');
		// 	}
		// }
		const userDoc = await User.findOneAndUpdate(
			{
				_id: id,
			},
			{
				...dataBody,
			},
			{
				new: true,
			},
		);
		return userDoc;
	}

	async deleteUser(id: string): Promise<IUser> {
		const user = await User.findById(id);
		if (!user) {
			throw new BadRequestError('account_not_found');
		}
		user.email = user.email + '_deleted_' + new Date().getTime();
		await user.save();
		await User.delete({
			_id: id,
		});
		return user.toJSON() as IUser;
	}

	async updateLockUser(id: string, locked: boolean): Promise<IUser> {
		const user = await UserService.updateLockUser(id, locked);
		return user;
	}

	// async updateUserPhoneById(
	// 	currentUser: ITokenPayload,
	// 	dataBody: IUpdateUserPhoneInterface,
	// ): Promise<void> {
	// 	const user = await UserService.getUserById(currentUser.id);
	// 	if (!user) {
	// 		throw new BadRequestError('account_not_found');
	// 	}
	// 	const checkPhoneExist = await UserService.findOneWithCondition({
	// 		phone: dataBody.phone,
	// 		_id: { $ne: currentUser.id },
	// 	});
	// 	if (checkPhoneExist) {
	// 		throw new FormRequestError('phone_already_exists', 'phone');
	// 	}
	// }

	// async resetUser(currentUser: ITokenPayload): Promise<void> {
	// 	await User.updateOne(
	// 		{ _id: currentUser.id },
	// 		{
	// 			phone: '',
	// 			isVerifiedPhone: false,
	// 			favourites: [],
	// 			unFavourites: [],
	// 		},
	// 	);
	// }
}
