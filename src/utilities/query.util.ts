export const buildQuery = (criteria: any) => {
	const query: { [key: string]: any } = {};
	if (criteria.email) {
		query.email = { $regex: criteria.email, $options: 'i' };
	}

	return query;
};
