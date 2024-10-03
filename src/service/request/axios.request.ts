import axios, {
	AxiosResponse,
	AxiosHeaders,
	RawAxiosRequestHeaders,
} from 'axios';

axios.defaults.headers.common['Content-Type'] = 'application/json';

export function setHeader(key: string, value: string): void {
	axios.defaults.headers.common[key] = value;
}

export async function get(
	url: string,
	header?: RawAxiosRequestHeaders | AxiosHeaders,
): Promise<AxiosResponse> {
	try {
		const response = await axios.get(url, {
			headers: header,
		});
		return response;
	} catch (error) {
		throw new Error(`Failed to get data from ${url}.`);
	}
}

export async function post<T>(
	url: string,
	data: T,
	header?: RawAxiosRequestHeaders | AxiosHeaders,
): Promise<AxiosResponse> {
	try {
		const response = await axios.post(url, data, {
			headers: header,
		});
		return response;
	} catch (error) {
		console.log(error);
		throw new Error(`Failed to post data from ${url}.`);
	}
}

export async function put<T>(
	url: string,
	data: T,
	header?: RawAxiosRequestHeaders | AxiosHeaders,
): Promise<AxiosResponse> {
	try {
		const response = await axios.put(url, data, {
			headers: header,
		});
		return response;
	} catch (error) {
		throw new Error(`Failed to put data from ${url}.`);
	}
}

export async function del(
	url: string,
	header?: RawAxiosRequestHeaders | AxiosHeaders,
): Promise<AxiosResponse> {
	try {
		const response = await axios.delete(url, {
			headers: header,
		});
		return response;
	} catch (error) {
		throw new Error(`Failed to delete data from ${url}.`);
	}
}
