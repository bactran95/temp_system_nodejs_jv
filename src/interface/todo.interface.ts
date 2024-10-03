import { ImageAttrs } from '@api/image/image.model';
import mongoose from 'mongoose';

export enum TodoStatusEnum {
	Pending = 'pending',
	Completed = 'completed',
	Cancelled = 'cancelled',
	Doing = 'doing',
}
export interface ITodo {
	// status: TodoStatusEnum;
	user_id: mongoose.Schema.Types.ObjectId;
	start_date: Date;
	end_date: Date;
	images: ImageAttrs[];
	image_urls?: string[];
	title: string;
	description: string;
}

export interface ICreateTodo {
	name: string;
	user_id: mongoose.Schema.Types.ObjectId;
	// status: TodoStatusEnum;
	start_time: Date;
	end_time: Date;
}

export interface IFilterTodo {
	name?: string;
	// status?: TodoStatusEnum;
	start_time?: Date;
	end_time?: Date;
	created_at?: Date;
}

export interface IUpdateTodoInterface {
	name: string;
	// status: TodoStatusEnum;
	start_time: Date;
	end_time: Date;
}

// export interface IUploadImage {
// 	name: string;
// 	status: TodoStatusEnum;
// 	start_time: Date;
// 	end_time: Date;
// }
