import env from '@env';

export const buildHtmlRegisterUser = (encrypted: string) => {
	const generateUrl = `${env.app.base_url}/api/verify?encrypted=${encrypted}`;
	return `<a href='${generateUrl}'>${generateUrl}</a>`;
};

export const buildImageUrl = (
	protocol: string,
	hostName: string,
	link: string,
) => {
	return `${protocol}://${hostName}/${link}`;
};
