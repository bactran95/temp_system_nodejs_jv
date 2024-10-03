export const resOK = (
	data: any,
	message: string = 'Success',
	total?: number,
	limit?: number,
	page?: number,
) => ({
	message,
	data,
	meta: {
		total: total || undefined,
		limit: limit || undefined,
		page: page || undefined,
	},
});

export const resErr = (
	message: string | string[],
	code?: string,
	errors?: any,
) => {
	return {
		message,
		code,
		errors,
	};
};
