import { IsArray, IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class UpdateUserRequest {
	@IsOptional()
	@IsEmail({}, { message: 'email_address_is_invalid' })
	email!: string;

	constructor(req: UpdateUserRequest) {
		Object.assign(this, req);
	}
}

export class UpdateFavouriteUserRequest {
	@IsArray()
	favourites!: [string];

	constructor(req: UpdateFavouriteUserRequest) {
		Object.assign(this, req);
	}
}

export class UpdatePhoneUserRequest {
	@IsNotEmpty({ message: 'phone_is_required' })
	@IsString()
	phone!: string;

	@IsNotEmpty()
	@IsString()
	countryCode!: string;

	constructor(req: UpdatePhoneUserRequest) {
		Object.assign(this, req);
	}
}

export class UpdateUnFavouriteUserRequest {
	@IsArray()
	unFavourites!: [string];

	constructor(req: UpdateUnFavouriteUserRequest) {
		Object.assign(this, req);
	}
}

export class UpdateWalletAddressUserRequest {
	@IsNotEmpty()
	@IsString()
	walletAddress!: string;

	constructor(req: UpdateWalletAddressUserRequest) {
		Object.assign(this, req);
	}
}
