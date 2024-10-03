import express from 'express';
import { ApplicationConfig } from './app.conf';
import { errorHandler } from '@middlewares/error-handler.middlewares';
import { seed } from 'src/seed/seed';
import { connectToDatabase } from './database.conf';
import { Routes } from './routes.conf';
import { AdminRoutes } from './admin-routes.conf';
import { NotFoundError, Logger } from 'common';

export class Config {
	public static async init(): Promise<express.Application> {
		const app = express();
		const router = express.Router();
		let s = performance.now();
		await connectToDatabase();
		let e = performance.now();
		Logger.info(`db init ${e - s}`);

		s = performance.now();
		await seed();
		e = performance.now();
		Logger.info(`run seed ${e - s}`);

		s = performance.now();
		ApplicationConfig.init(app);
		e = performance.now();
		Logger.info(`app init ${e - s}`);

		s = performance.now();
		Routes.init(app, router);
		e = performance.now();
		Logger.info(`router user init ${e - s}`);


		s = performance.now();
		AdminRoutes.init(app, router);
		e = performance.now();
		Logger.info(`router admin init ${e - s}`);
		app.all('*', (req, res, next) => {
			next(new NotFoundError());
		});

		app.use(errorHandler);

		return app;
	}
}
