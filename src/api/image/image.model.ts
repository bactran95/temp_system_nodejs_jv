import { TodoStatusEnum } from '@interfaces/todo.interface';
import mongoose from 'mongoose';
import MongooseDelete, {
	SoftDeleteModel,
	SoftDeleteDocument,
} from 'mongoose-delete';

export interface ImageAttrs {
	name: string;
	link: string;
}

interface ImageDoc extends SoftDeleteDocument {
	name: string;
	link: string;
}

export const imageSchema = new mongoose.Schema<ImageDoc>(
	{
		name: {
			type: String,
			required: true,
		},
		link: {
			type: String,
			required: true,
		},
	},
	{
		timestamps: {
			createdAt: 'created_at', // Use `created_at` to store the created date
			updatedAt: 'updated_at', // and `updated_at` to store the last updated date
		},
	},
);
