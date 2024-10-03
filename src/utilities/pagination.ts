// import {
// 	IPagination,
// 	IPaginationHeader,
// } from '@interfaces/pagination.interface';
// import { PAGE, PER_PAGE } from '@constances/constant';

// export class PaginationHeaderUtil {
// 	public static makeMetaRes(
// 		pagination: IPagination,
// 		totalCount: number,
// 	): IPaginationHeader {
// 		const page = +pagination.page;
// 		const perPage = +pagination.perPage;
// 		const pagesCount = Math.ceil(totalCount / perPage);

// 		return {
// 			page: page,
// 			totalCount: totalCount,
// 			pagesCount: pagesCount,
// 			perPage: perPage,
// 			nextPage: pagesCount === 0 || page === pagesCount ? 0 : page + 1,
// 		};
// 	}

// 	public static createPagination = (
// 		page: string | number,
// 		perPage: string | number,
// 	): IPagination => {
// 		page = page ? +page : PAGE;
// 		perPage = perPage ? +perPage : PER_PAGE;

// 		const startIndex = (page - 1) * perPage;
// 		const endIndex = page * perPage;

// 		return {
// 			page,
// 			perPage,
// 			startIndex,
// 			endIndex,
// 		};
// 	};
// }
