import { IFilterTodo } from '@interfaces/todo.interface';
import { verifyToken } from '@middlewares/auth.middlewares';
import { BadRequestError, resOK, upload } from 'common';
import { NextFunction, Request, Response, Router } from 'express';
import mongoose, { SortOrder } from 'mongoose';
import { TodoAttrs } from '../todo.model';
import { TodoController } from './todo.controller';
import { ImageAttrs } from '@api/image/image.model';
import { buildImageUrl } from '@utilities/string.util';

export class TodoRouter {
	private controller = new TodoController();

	init(router: Router): void {
		const todoRouter = Router();
		todoRouter.get('/', this.getTodos.bind(this));
		todoRouter.post(
			'/',
			upload.array('image_files[]', 5),
			this.createTodo.bind(this),
		);
		todoRouter.delete('/:id', this.deleteTodo.bind(this));
		todoRouter.get('/:id', this.getTodoById.bind(this));
		todoRouter.post(
			'/:id',
			upload.array('image_files[]', 5),
			this.updateTodo.bind(this),
		);
		// todoRouter.patch(
		// 	'/:id/image',
		// 	upload.single('image'),
		// 	this.updateTodo.bind(this),
		// );
		router.use('/v1/todos', verifyToken, todoRouter);
	}

	async getTodos(req: Request, res: Response, next: NextFunction) {
		try {
			const page = Number(req.query.page) - 1 || 0;
			const limit = Number(req.query.limit) || 10;
			const sort = req.query.sort?.toString() || 'created_at';
			const order: SortOrder = (req.query.orderBy?.toString() ||
				'desc') as SortOrder;
			const filter: IFilterTodo = {};
			if (req.query.name) {
				filter.name = req.query.name as string;
			}
			const todos = await this.controller.getTodos(filter, {
				limit: limit,
				page: page,
				sort,
				order,
			});
			const hostName = req.headers.host;
			const protocol = req.protocol;
			if (todos.items && todos.items.length > 0) {
				todos.items.forEach((todo) => {
					todo.images.forEach((image) => {
						image.link = buildImageUrl(protocol, hostName!, image.link);
					});
				});
			}

			const totalPage = Math.ceil(todos.total_items / limit);

			res.status(200).json(
				resOK(
					todos,
					'Get Todos successfully',
					todos.total_items,
					limit,
					page + 1,
					totalPage,
				),
			);
		} catch (error) {
			next(error);
		}
	}

	async getTodoById(req: Request, res: Response, next: NextFunction) {
		try {
			const todoId = req.params.id;
			const todo = await this.controller.getTodoById(todoId);
			console.log(todo);
			if (todo && todo.image_urls && todo.image_urls.length > 0) {
				const hostName = req.headers.host;
				const protocol = req.protocol;
				console.log(hostName, protocol);
				todo.image_urls = todo.image_urls.map((image) => {
					return buildImageUrl(protocol, hostName!, image);
				});
			}
			res.status(200).json(resOK(todo));
		} catch (error) {
			next(error);
		}
	}

	async createTodo(req: Request, res: Response, next: NextFunction) {
		try {
			if (!req.files || req.files.length === 0) {
				throw new BadRequestError('image_is_required');
			}
			const images: ImageAttrs[] = [];

			Object.values(req.files).forEach((file: { filename: string; originalname: string }) => {
				images.push({
					link: file.filename,
					name: file.originalname,
				});
			});

			const dataBody: TodoAttrs = {
				...req.body,
				user_id: req.currentUser.id,
				images,
			};

			const todo = await this.controller.createTodo(dataBody);
			if (todo && todo.image_urls && todo.image_urls.length > 0) {
				const hostName = req.headers.host;
				const protocol = req.protocol;
				console.log(hostName, protocol);
				todo.image_urls = todo.image_urls.map((image) => {
					return buildImageUrl(protocol, hostName!, image);
				});
			}
			res.status(200).json(resOK({ todo }));
		} catch (error) {
			next(error);
		}
	}

	async updateTodo(req: Request, res: Response, next: NextFunction) {
		try {
			const dataBody: TodoAttrs = req.body;
			if (req.files && Array.isArray(req.files) && req.files.length > 0) {
				dataBody.images = [];
				Object.values(req.files).forEach((file: { filename: string; originalname: string }) => {
					dataBody.images.push({
						link: file.filename,
						name: file.originalname,
					});
				});
			}
			dataBody.user_id = req.currentUser.id;
			const todo = await this.controller.updateTodoById(
				req.params.id?.toString(),
				dataBody,
			);

			if (todo && todo.image_urls && todo.image_urls.length > 0) {
				const hostName = req.headers.host;
				const protocol = req.protocol;
				console.log(hostName, protocol);
				todo.image_urls = todo.image_urls.map((image: string) => {
					return buildImageUrl(protocol, hostName!, image);
				});
			}

			res.status(200).json(resOK(todo));
			} catch (error) {
			next(error);
		}
	}

	// async updateImage(req: Request, res: Response, next: NextFunction) {
	// 	try {
	// 		const Todo = await this.controller.updateTodoById(
	// 			req.params.id?.toString(),
	// 			req.body,
	// 		);
	// 		res.status(200).json(resOK(Todo));
	// 	} catch (error) {
	// 		next(error);
	// 	}
	// }

	async deleteTodo(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const Todo = await this.controller.deleteTodo(
				req.params.id?.toString(),
			);
			res.status(200).json(resOK(Todo));
		} catch (error) {
			next(error);
		}
	}
}
