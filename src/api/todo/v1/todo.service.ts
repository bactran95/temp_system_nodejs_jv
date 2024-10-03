import { Todo, TodoAttrs } from '@api/todo/todo.model';
import { ITodo } from '@interfaces/todo.interface';

export async function createTodo(dataBody: any): Promise<ITodo> {
	const todo = Todo.build(dataBody);
	const todoDoc = await todo.save();
	return todoDoc.toJSON();
}

export async function getTodoById(_id: string): Promise<ITodo | null> {
	const todo = await Todo.findOne({ _id });

	return todo?.toJSON() as ITodo;
}

export async function findOneWithCondition(
	query = {},
	projection = {},
): Promise<ITodo | null> {
	return await Todo.findOne(query, projection);
}

export async function updateTodoById(_id: string, data: any): Promise<void> {
	await Todo.updateOne({ _id }, data);
}

export async function updateUserById(
	_id: string,
	data: any,
): Promise<ITodo | null> {
	return await Todo.findOne({ _id }, data);
}
