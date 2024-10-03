import { GRANT_TYPE } from '@constances/enum';
import env from '@env';
import { del, post } from '../../request';

export const getAccesTokenFromLine = async (code: string): Promise<any> => {
	const { data } = await post(
		`${env.lineLogin.lineOauthUrl}/token`,
		{
			grant_type: GRANT_TYPE.CODE,
			code,
			client_id: env.lineLogin.clientId,
			client_secret: env.lineLogin.clientSecret,
			redirect_uri: env.lineLogin.redirectUri,
		},
		{
			'Content-Type': 'application/x-www-form-urlencoded',
		},
	);
	return data;
};

export const getProfile = async (idToken: string): Promise<any> => {
	const { data: profile } = await post(
		`${env.lineLogin.lineOauthUrl}/verify`,
		{
			id_token: idToken,
			client_id: env.lineLogin.clientId,
		},
		{
			'Content-Type': 'application/x-www-form-urlencoded',
		},
	);

	return profile;
};
