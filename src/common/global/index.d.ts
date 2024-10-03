import { ITokenPayload } from '@interfaces/authen.interface';

declare global {
	namespace Express {
		interface Request {
			currentUser: ITokenPayload;
		}
	}
}
