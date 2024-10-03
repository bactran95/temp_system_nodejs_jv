import { IsEmail, IsNotEmpty, Length } from 'class-validator';

export class ForgotPasswordRequest {
	@IsNotEmpty()
	@IsEmail()
	@Length(8, 50)
	email!: string;

	constructor(req: ForgotPasswordRequest) {
		Object.assign(this, req);
	}
}
