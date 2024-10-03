import compression from 'compression';
import cors from 'cors';
import express, { Response } from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import env from '@env';
import path from 'path';
import i18n from 'i18n';
import cookieParser from 'cookie-parser';
export class ApplicationConfig {
	public static init(application: express.Application): void {
		// --- Middle wares
		application.use(express.json({ limit: env.app.bodyPayloadLimit }));
		application.use(
			express.urlencoded({
				limit: env.app.bodyPayloadLimit,
				extended: true,
			}),
		);
		application.use(express.raw({ limit: env.app.bodyPayloadLimit }));

		application.use(helmet());
		application.use(compression());
		application.use(cors());
		application.use(cookieParser(env.app.cookieSecret));
		const staticOptions = {
			setHeaders: (res: Response) => {
				res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
			},
		};

		application.use(
			express.static(path.join(process.cwd(), 'uploads'), staticOptions),
		);

		i18n.configure({
			locales: ['jp', 'en'],
			directory: path.join(process.cwd(), 'src', 'locales'),
			defaultLocale: 'jp',
			header: 'accept-language',
			updateFiles: false,
		});

		application.use(i18n.init);

		application.use((req, res, next) => {
			const preferredLocale = req.headers['accept-language'] || 'jp';
			req.setLocale(preferredLocale);
			next();
		});

		if (env.app.debugLog) {
			application.use(
				morgan('dev', {
					skip: (req, res) => {
						return res.statusCode < 400;
					},
					stream: process.stderr,
				}),
			);

			application.use(
				morgan('dev', {
					skip: (req, res) => {
						return res.statusCode >= 400;
					},
					stream: process.stdout,
				}),
			);
		}
	}
}
