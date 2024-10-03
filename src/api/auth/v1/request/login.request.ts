import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginRequest {
	@IsString()
	@IsEmail({}, { message: 'email_is_invalid' })
	@IsNotEmpty({
		message: 'you_must_enter_email_and_password',
	})
	email!: string;

	@IsNotEmpty({
		message: 'you_must_enter_email_and_password',
	})
	@IsString()
	password!: string;

	constructor(req: LoginRequest) {
		Object.assign(this, req);
	}
}
