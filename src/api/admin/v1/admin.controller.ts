import { Admin, AdminDoc } from '@api/admin/admin.model';
import { getToken } from '@api/auth/v1/auth.service';
import env from '@env';
import { BadRequestError, NotFoundError, EncUtil } from 'common';
import * as AdminService from './admin.service';

export class AdminController {
	async getAdminById(adminId: string): Promise<AdminDoc> {
		const admin = await AdminService.getAdminById(adminId);
		if (!admin) {
			throw new BadRequestError('admin_not_found');
		}
		return admin;
	}

	async signIn(signInBody: any): Promise<String> {
		const existingAdmin = await Admin.findOne({
			email: signInBody.email,
		});
		if (existingAdmin === null) {
			throw new NotFoundError('email_not_found');
		}

		const isValidPassword = await EncUtil.comparePassword(
			signInBody.password,
			existingAdmin.password!,
		);

		if (!isValidPassword) {
			throw new NotFoundError('the_password_is_in_correct');
		}

		return getToken(
			{
				id: existingAdmin.id,
			},
			env.app.jwtExpiredIn,
			env.app.jwtSecret,
		);
	}
}
