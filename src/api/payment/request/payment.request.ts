import {
	IsNotEmpty,
	IsNumber,
	IsString
} from 'class-validator';

export class PaymentRequest {
	@IsString()
	@IsNotEmpty()
	token!: string;

	@IsNumber()
	@IsNotEmpty()
	amount!: number;

	constructor(req: PaymentRequest) {
		Object.assign(this, req);
	}
}
