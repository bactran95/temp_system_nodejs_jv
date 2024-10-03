import { IsEmail, IsNotEmpty } from 'class-validator';

export class CreateUserRequest {
	@IsNotEmpty({ message: 'email_is_a_required_field' })
	@IsEmail({}, { message: 'email_address_is_invalid' })
	email!: string;


	constructor(req: CreateUserRequest) {
		Object.assign(this, req);
	}
}
