import mongoose from 'mongoose';
import env from '@env';
import { Logger } from 'common';

const dbConfig = env.database;

export const connectToDatabase = async () => {
	try {
		await mongoose.connect(dbConfig.mongoUri);
		Logger.info('connected to mongodb');
	} catch (error) {
		const message =
			(error as Error).message || 'something went wrong with database';
		Logger.error(`Unable to connect to the database ${message}`);
		throw error;
	}
};
