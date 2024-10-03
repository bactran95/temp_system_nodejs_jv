import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshTokenRequest {
	@IsNotEmpty({
		message: 'you_must_enter_refresh_token',
	})
	@IsString()
	refresh_token!: string;

	constructor(req: RefreshTokenRequest) {
		Object.assign(this, req);
	}
}
