import mongoose from 'mongoose';
import MongooseDelete, {
	SoftDeleteModel,
	SoftDeleteDocument,
} from 'mongoose-delete';

export interface UserAttrs {
	email: string;
	first_name?: string;
	last_name?: string;
	phone_number?: string;
	password?: string;
	locked?: boolean;
	picture?: string;
	user_line_id?: string;
	address?: string;
	note?: string;
}

interface UserModel extends SoftDeleteModel<UserDoc> {
	build(attrs: UserAttrs): UserDoc;
}

interface UserDoc extends SoftDeleteDocument {
	email: string;
	first_name?: string;
	last_name?: string;
	phone_number?: string;
	password?: string;
	locked?: boolean;
	picture?: string;
	user_line_id?: string;
	address?: string;
	note?: string;
}

const userSchema = new mongoose.Schema<UserDoc>(
	{
		email: {
			type: String,
			required: true,
		},
		user_line_id: {
			type: String,
			required: false,
		},
		picture: {
			type: String,
			required: false,
		},
		password: {
			type: String,
			required: false,
		},
		first_name: {
			type: String,
			required: false,
		},
		last_name: {
			type: String,
			required: false,
		},
		phone_number: {
			type: String,
			required: false,
		},
		locked: {
			type: Boolean,
			default: false,
		},
		address: {
			type: String,
			default: false,
		},
		note: {
			type: String,
			default: false,
		}
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
		collection: 'users',
	},
);

userSchema.plugin(MongooseDelete, { deletedAt: true, overrideMethods: true });

userSchema.statics.build = (attrs: UserAttrs) => {
	return new User(attrs);
};

const User = mongoose.model<UserDoc, UserModel>('User', userSchema); // generic syntax inside a typescript

export { User };
