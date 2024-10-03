import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AdminSignInRequest {
	@IsNotEmpty({ message: 'email_is_a_required_field' })
	@IsEmail({}, { message: 'email_address_is_invalid' })
	email!: string;

	@IsNotEmpty({
		message: 'you_must_enter_email_and_password',
	})
	@IsString()
	password!: string;

	constructor(req: AdminSignInRequest) {
		Object.assign(this, req);
	}
}
