import path from 'path';
import * as dotenv from 'dotenv';
dotenv.config({
	path: path.join(process.cwd(), '.env'),
});
import { Logger } from 'common';
import { App } from './src/app';

async function main() {
    try {
		process.on('SIGTERM', () => {
			Logger.info(`Process ${process.pid} received a SIGTERM signal`);
			process.exit(0);
		});

		process.on('SIGINT', () => {
			Logger.info(`Process ${process.pid} has been interrupted`);
			process.exit(0);
		});

		process.on('uncaughtException', (err) => {
            Logger.error(`Uncaught Exception: ${err.message}`);
        });

		process.on('unhandledRejection', (reason, promise) => {
			Logger.error(`Unhandled rejection at ${promise} reason: ${reason}`);
		});

		await App.run();
	} catch (error) {
		const message = (error as Error).message || 'Error while running the application';
		Logger.error(`Error while running the application ${message}`);
	}
}

main();
