export function isEmpty(obj: any) {
	return obj && Object.keys(obj).length === 0 && obj.constructor === Object;
}

export function isObject(obj: any) {
	return typeof obj === 'object' && obj !== null;
}

export function trimObject(obj: any) {
	for (let key in obj) {
		if (typeof obj[key] === 'string') {
			obj[key] = obj[key].trim();
		}
	}
	return obj;
}
