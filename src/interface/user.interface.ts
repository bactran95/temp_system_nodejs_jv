export interface IUser {
	id: string;
	email: string;
	password: string;
	name: string;
}

export interface ICreateUser {
	name?: string;
	email: string;
	password: string;
	first_name?: string;
	last_name?: string;
	phone_number?: string;
}

export interface IUpdateUserInterface {
	// email: string;
	// avatarUrl: string;
	name: string;
	first_name: string;
	last_name: string;
	phone_number: string;
}

export interface IUpdateUserPhoneInterface {
	phone_number: string;
}

export interface IFilterUser {
	email?: string;
}

export interface ICreateUserWithLine {
	email: string;
	user_line_id: string;
	name: string;
	picture: string;
}
