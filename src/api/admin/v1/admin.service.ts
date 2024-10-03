import { Admin, AdminDoc } from '@api/admin/admin.model';

export async function getAdminById(_id: string): Promise<AdminDoc | null> {
	return await Admin.findOne({ _id });
}
