import { createTransport, TransportOptions } from 'nodemailer';
import env from '@env';
import { Logger } from 'common';

const transport = createTransport({
	host: env.mail.host,
	port: env.mail.port,
	auth: {
		user: env.mail.user,
		pass: env.mail.pass,
	},
} as TransportOptions);

export const sendMail = async (
	toUsers: string,
	subject: string,
	text?: string,
	html?: string,
) => {
	try {
		const info = await transport.sendMail({
			from: env.mail.from,
			to: toUsers,
			subject,
			text,
			html,
		});

		return info;
	} catch (error: unknown) {
		Logger.error(error as string, 'sendMail');
	}
};
