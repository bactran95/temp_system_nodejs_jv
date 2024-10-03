import { User } from '@api/users/user.model';
import { ICreateUserWithLine, IUser } from '@interfaces/user.interface';

export async function createUser(dataBody: any): Promise<IUser> {
	const user = User.build(dataBody);
	const userDoc = await user.save();
	return userDoc.toJSON();
}

export async function getUserById(_id: string): Promise<IUser | null> {
	return await User.findOne({ _id });
}

export async function findUserByEmailAndCreate(
	dataBody: ICreateUserWithLine,
): Promise<IUser> {
	const user = await User.findOne({ email: dataBody.email });
	if (user && user.user_line_id) {
		return user.toJSON();
	}

	const userCreate = await User.create(dataBody);
	return userCreate.toJSON();
}

export async function findOneWithCondition(
	query = {},
	projection = {},
): Promise<IUser | null> {
	return await User.findOne(query, projection);
}

export async function updateUserVerifiedById(_id: string): Promise<void> {
	await User.updateOne({ _id }, { is_verified_phone: true });
}

export async function updateUserById(
	_id: string,
	data: any,
): Promise<IUser | null> {
	return await User.findOne({ _id }, data);
}

export async function updateLockUser(
	id: string,
	locked: boolean,
): Promise<IUser> {
	const user = await User.findById(id);
	if (!user) {
		throw new Error('User not found');
	}
	user.locked = locked;
	user.save();
	return user.toJSON();
}
