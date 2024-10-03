import { Admin } from '@api/admin/admin.model';
import { Logger, EncUtil } from 'common';

export async function seed() {
	try {
		const password = process.env.PASSWORD_ADMIN || 'admin@123';

		const checkAdmin = await Admin.findOne({
			email: process.env.EMAIL_ADMIN || 'admin@javis.vn',
		});
		if (!checkAdmin) {
			const newAdmin = new Admin({
				email: process.env.EMAIL_ADMIN || 'admin@javis.vn',
				password: await EncUtil.createHash(password),
			});
			await newAdmin.save();

			Logger.info('Seeder successfully');
		} else {
			Logger.info('Already seeded');
		}
	} catch (error) {
		Logger.error('Seeder failed!');
		throw error;
	}
}
