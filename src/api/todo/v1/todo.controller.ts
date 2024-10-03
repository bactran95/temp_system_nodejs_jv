import { IFilterPaging } from '@interfaces/Base.interface';
import { IPagination } from '@interfaces/IPagination';
import {
	IFilterTodo,
	ITodo,
	IUpdateTodoInterface,
} from '@interfaces/todo.interface';
import { BadRequestError, buildQuery } from 'common';
import { Todo, TodoAttrs } from '../todo.model';
import * as TodoService from './todo.service';
import * as fs from 'fs';
import path from 'path';
import env from '@env';
export class TodoController {
	async createTodo(dataBody: TodoAttrs): Promise<ITodo> {
		return TodoService.createTodo(dataBody);
	}

	async getTodos(
		filter: IFilterTodo,
		paging: IFilterPaging,
	): Promise<IPagination<ITodo>> {
		const query = buildQuery(filter);
		const total_items = await Todo.countDocuments(query);
		const todo = await Todo.find(query)
			.skip(paging.page * paging.limit)
			.limit(paging.limit)
			.sort({ [paging.sort]: paging.order })
			.exec();

		return {
			total_items,
			items: todo as ITodo[],
		};
	}

	async getTodoById(_id: string): Promise<ITodo | null> {
		const todo = await TodoService.getTodoById(_id);
		if (!todo) {
			throw new BadRequestError('todo_not_found');
		}
		return todo;
	}

	async updateTodoById(todoId: string, dataBody: TodoAttrs): Promise<any> {
		const todo = await TodoService.getTodoById(todoId);
		if (!todo) {
			throw new BadRequestError('todo_not_found');
		}

		const todoDoc = await Todo.findOneAndUpdate(
			{
				_id: todoId,
			},
			{
				$set: { images: dataBody.images || todo.images },
				start_time: dataBody.start_date || todo.start_date,
				end_time: dataBody.end_date || todo.end_date,
				title: dataBody.title || todo.title,
				description: dataBody.description || todo.description,
			},
			{
				new: true,
			},
		);

		if (todo.image_urls && todo.image_urls.length > 0) {
			todo.image_urls.forEach((image) => {
				fs.unlinkSync(
					path.join(
						env.app.root_path,
						`${process.env.UPLOAD_DIR}/${image}`,
					),
				);
			});
		}
		return todoDoc;
	}

	async deleteTodo(id: string): Promise<ITodo> {
		const todo = await Todo.findById(id);
		if (!todo) {
			throw new BadRequestError('todo_not_found');
		}

		if (todo.images && todo.images.length > 0) {
			todo.images.forEach((image) => {
				fs.unlinkSync(
					path.join(
						env.app.root_path,
						`${process.env.UPLOAD_DIR}/${image.link}`,
					),
				);
			});
		}

		await todo.delete();
		return todo.toJSON() as ITodo;
	}

	// async uploadImage(id: string, file: Express.Multer.File): Promise<ITodo> {
	// 	const todo = await Todo.findById(id);
	// 	if (!todo) {
	// 		throw new BadRequestError('todo_not_found');
	// 	}
	// 	todo.images = {
	// 		link: file.filename,
	// 		name: file.originalname,
	// 	};
	// 	await todo.save();
	// 	return todo.toJSON() as ITodo;
	// }
}
