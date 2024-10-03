import http from 'http';
import { Config } from './config';
import env from '@env';
import { Logger } from 'common';

export class App {
	public static async run(): Promise<void> {
		const port = env.app.port;
		const app = await Config.init();
		const server = http.createServer(app);
		server.listen(port, () => {
			Logger.info(`App listening on port ${port}`);
		});
	}
}
