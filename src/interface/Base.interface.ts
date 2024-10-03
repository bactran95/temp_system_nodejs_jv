import { SortOrder } from 'mongoose';

export interface IFilterPaging {
	limit: number;
	page: number;
	sort: string;
	order: SortOrder;
}
