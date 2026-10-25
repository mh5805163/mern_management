import app, { connectDatabase } from '../src/server.js';
let databaseConnection;
export default async function handler(req, res) {
    databaseConnection ??= connectDatabase();
    await databaseConnection;
    return app(req, res);
}
