import {
	IsEmail,
	IsNotEmpty,
	IsString,
	Length
} from 'class-validator';

export class RegisterRequest {
	@IsNotEmpty({ message: 'email_is_a_required_field' })
	@IsEmail({}, { message: 'email_address_is_invalid' })
	email!: string;

	@IsNotEmpty({ message: 'password_is_a_required_field' })
	@IsString()
	@Length(6, 50, { message: 'please_enter_between_6_and_50_characters' })
	password!: string;

	@IsNotEmpty({ message: 'first_name_is_a_required_field' })
	first_name!: string;

	@IsNotEmpty({ message: 'last_name_is_a_required_field' })
	last_name!: string;

	@IsNotEmpty({ message: 'phone_number_is_a_required_field' })
	phone_number!: string;

	constructor(req: RegisterRequest) {
		Object.assign(this, req);
	}
}
