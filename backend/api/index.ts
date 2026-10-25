import type { VercelRequest, VercelResponse } from '@vercel/node'
import app, { connectDatabase } from '../src/server.js'

let databaseConnection: Promise<void> | undefined

export default async function handler(req: VercelRequest, res: VercelResponse) {
  databaseConnection ??= connectDatabase()
  await databaseConnection
  return app(req, res)
}
