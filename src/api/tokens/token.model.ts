import mongoose, { Schema } from 'mongoose';
import MongooseDelete, {
	SoftDeleteDocument,
	SoftDeleteModel,
} from 'mongoose-delete';

export interface TokenAttrs {
	userId: string;
	token?: string;
	created_at?: Date;
}

interface TokenModel extends SoftDeleteModel<TokenDoc> {
	build(attrs: TokenAttrs): TokenDoc;
}

interface TokenDoc extends SoftDeleteDocument {
	user_id: string;
	token?: string;
	created_at?: Date;
}

const tokenSchema = new Schema(
	{
		userId: {
			type: Schema.Types.ObjectId,
			required: true,
			ref: 'user',
		},
		token: {
			type: String,
			required: false,
		},
		created_at: {
			type: Date,
			default: Date.now,
			expires: 3600,
		},
	},
	{
		toJSON: {
			transform(doc, ret) {
				ret.id = ret._id;
				delete ret._id;
				delete ret.__v; // another way is set versionKey is false
			},
		},
		timestamps: {
			createdAt: 'created_at', // Use `created_at` to store the created date
			updatedAt: 'updated_at', // and `updated_at` to store the last updated date
		},
		collection: 'tokens',
	},
);

tokenSchema.plugin(MongooseDelete, { deletedAt: true, overrideMethods: true });

tokenSchema.statics.build = (attrs: TokenAttrs) => {
	return new Token(attrs);
};

const Token = mongoose.model<TokenDoc, TokenModel>('token', tokenSchema);

export { Token };
