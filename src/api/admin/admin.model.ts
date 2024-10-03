import mongoose from 'mongoose';
import MongooseDelete, {
	SoftDeleteModel,
	SoftDeleteDocument,
} from 'mongoose-delete';

export interface AdminAttrs {
	email: string;
	password: string;
	created_at?: Date;
	updated_at?: Date;
}

interface AdminModel extends SoftDeleteModel<AdminDoc> {
	build(attrs: AdminAttrs): AdminDoc;
}

export interface AdminDoc extends SoftDeleteDocument {
	email: string;
	password: string;
}

const adminSchema = new mongoose.Schema<AdminDoc>(
	{
		email: {
			type: String,
			required: true,
		},
		password: {
			type: String,
			required: true,
		},
	},
	{
		toJSON: {
			transform(doc, ret) {
				ret.id = ret._id;
				delete ret._id;
				delete ret.password;
				delete ret.__v; // another way is set versionKey is false
			},
		},
		timestamps: {
			createdAt: 'created_at', // Use `created_at` to store the created date
			updatedAt: 'updated_at', // and `updated_at` to store the last updated date
		},
		collection: 'admins',
	},
);

adminSchema.plugin(MongooseDelete, { deletedAt: true, overrideMethods: 'all' });

adminSchema.statics.build = (attrs: AdminAttrs) => {
	return new Admin(attrs);
};

const Admin = mongoose.model<AdminDoc, AdminModel>('Admin', adminSchema); // generic syntax inside a typescript

export { Admin };
