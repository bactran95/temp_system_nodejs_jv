import { ImageAttrs, imageSchema } from '@api/image/image.model';
import mongoose from 'mongoose';
import MongooseDelete, {
	SoftDeleteDocument,
	SoftDeleteModel,
} from 'mongoose-delete';

export interface TodoAttrs {
	// status: TodoStatusEnum;
	user_id: string;
	start_date: Date;
	end_date: Date;
	images: ImageAttrs[];
	title: string;
	description: string;
}

interface TodoModel extends SoftDeleteModel<TodoDoc> {
	build(attrs: TodoAttrs): TodoDoc;
}

interface TodoDoc extends SoftDeleteDocument {
	// status: TodoStatusEnum;
	user_id: mongoose.Schema.Types.ObjectId;
	start_date: Date;
	end_date: Date;
	images: ImageAttrs[];
	title: string;
	description: string;
}

const todoSchema = new mongoose.Schema<TodoDoc>(
	{
		images: {
			type: [imageSchema],
			required: false,
		},
		title: {
			type: String,
			required: false,
		},
		description: {
			type: String,
			required: false,
		},
		// status is an enum
		// status: {
		// 	type: String,
		// 	required: true,
		// 	enum: Object.values(TodoStatusEnum),
		// 	default: TodoStatusEnum.Pending,
		// },
		user_id: {
			type: mongoose.Schema.Types.ObjectId,
			required: true,
			ref: 'User',
		},
		start_date: {
			type: Date,
			required: true,
		},
		end_date: {
			type: Date,
			required: true,
		},
	},
	{
		toJSON: {
			transform(doc, ret) {
				ret.id = ret._id;
				ret.image_urls = [];
				if (ret.images && ret.images.length > 0) {
					ret.image_urls = ret.images.map((image: any) => {
						return  image.link;
					});
				}
				delete ret.images;
				delete ret._id;
				delete ret.__v; // another way is set versionKey is false
			},
		},
		timestamps: {
			createdAt: 'created_at', // Use `created_at` to store the created date
			updatedAt: 'updated_at', // and `updated_at` to store the last updated date
		},
		collection: 'todos',
	},
);

todoSchema.plugin(MongooseDelete, { deletedAt: true, overrideMethods: true });

todoSchema.statics.build = (attrs: TodoAttrs) => {
	return new Todo(attrs);
};

const Todo = mongoose.model<TodoDoc, TodoModel>('Todo', todoSchema); // generic syntax inside a typescript

export { Todo };
