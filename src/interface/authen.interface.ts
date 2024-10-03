import { AxiosResponse } from 'axios';

export interface ITokenPayload {
	id: string;
	iat?: string;
	exp?: string;
}

export interface ISignUpInterface {
	email: string;
	password: string;
	first_name: string;
	last_name: string;
	phone_number: string;
}

export interface ISignInInterface {
	email: string;
	password: string;
}

export interface IProfileInstargram {
	id?: string;
	email?: string;
}

export interface IProfileTwitter {
	id: string;
	name: string;
	email: string;
}

export interface ResponeGetMe extends AxiosResponse {
	data: {
		id: string;
		email: string;
		name?: string;
	};
}

export interface IToken {
	access_token: string;
	refresh_token: string;
}
