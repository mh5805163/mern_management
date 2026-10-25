import 'dotenv/config'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import express, { type NextFunction, type Request, type Response } from 'express'
import helmet from 'helmet'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import { z } from 'zod'

const app = express()
const port = Number(process.env.PORT ?? 4000)
const clientOrigin = process.env.CLIENT_ORIGIN ?? 'http://localhost:3000'
const jwtSecret = process.env.JWT_SECRET ?? 'development-only-secret'

const userSchema = new mongoose.Schema({ name: { type: String, required: true, trim: true }, email: { type: String, required: true, unique: true, lowercase: true, index: true }, passwordHash: { type: String, required: true }, role: { type: String, enum: ['Admin', 'Organizer', 'Exhibitor', 'Attendee'], default: 'Attendee' } }, { timestamps: true })
const eventSchema = new mongoose.Schema({ name: { type: String, required: true, trim: true }, type: { type: String, required: true }, date: { type: String, required: true }, venue: { type: String, required: true }, organizer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, status: { type: String, enum: ['Draft', 'Published', 'Live'], default: 'Draft' }, attendeeCount: { type: Number, default: 0 }, boothCount: { type: Number, default: 0 } }, { timestamps: true })
eventSchema.index({ status: 1, createdAt: -1 })
const User = mongoose.model('User', userSchema)
const Event = mongoose.model('Event', eventSchema)
type AuthRequest = Request & { user?: { id: string; role: string } }
const publicUser = (user: InstanceType<typeof User>) => ({ id: user.id, name: user.name, email: user.email, role: user.role })
const tokenFor = (user: InstanceType<typeof User>) => jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: '2h' })
const auth = (req: AuthRequest, res: Response, next: NextFunction) => { const header = req.headers.authorization; if (!header?.startsWith('Bearer ')) return res.status(401).json({ data: null, error: 'Authentication required' }); try { req.user = jwt.verify(header.slice(7), jwtSecret) as { id: string; role: string }; next() } catch { return res.status(401).json({ data: null, error: 'Invalid or expired token' }) } }
const requireRole = (...roles: string[]) => (req: AuthRequest, res: Response, next: NextFunction) => req.user && roles.includes(req.user.role) ? next() : res.status(403).json({ data: null, error: 'Insufficient permissions' })

app.use(helmet())
app.use(cors({ origin: clientOrigin }))
app.use(express.json({ limit: '1mb' }))
app.get('/api/health', (_req, res) => res.json({ data: { status: 'ok', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }, error: null }))
app.post('/api/auth/register', async (req, res, next) => { try { const input = z.object({ name: z.string().min(2), email: z.email(), password: z.string().min(8), role: z.enum(['Admin', 'Organizer', 'Exhibitor', 'Attendee']).default('Attendee') }).parse(req.body); const exists = await User.exists({ email: input.email.toLowerCase() }); if (exists) return res.status(409).json({ data: null, error: 'Email already registered' }); const user = await User.create({ ...input, email: input.email.toLowerCase(), passwordHash: await bcrypt.hash(input.password, 12) }); res.status(201).json({ data: { user: publicUser(user), token: tokenFor(user) }, error: null }) } catch (error) { next(error) } })
app.post('/api/auth/login', async (req, res, next) => { try { const input = z.object({ email: z.email(), password: z.string().min(8) }).parse(req.body); const user = await User.findOne({ email: input.email.toLowerCase() }); if (!user || !(await bcrypt.compare(input.password, user.passwordHash))) return res.status(401).json({ data: null, error: 'Invalid email or password' }); res.json({ data: { user: publicUser(user), token: tokenFor(user) }, error: null }) } catch (error) { next(error) } })
app.get('/api/auth/me', auth, async (req: AuthRequest, res, next) => { try { const user = await User.findById(req.user!.id); if (!user) return res.status(404).json({ data: null, error: 'User not found' }); res.json({ data: publicUser(user), error: null }) } catch (error) { next(error) } })
app.get('/api/events', async (_req, res, next) => { try { res.json({ data: await Event.find().sort({ createdAt: -1 }).populate('organizer', 'name'), error: null }) } catch (error) { next(error) } })
app.post('/api/events', auth, requireRole('Admin', 'Organizer'), async (req: AuthRequest, res, next) => { try { const input = z.object({ name: z.string().min(2), type: z.string().min(2), date: z.string().min(2), venue: z.string().min(2), status: z.enum(['Draft', 'Published', 'Live']).default('Draft') }).parse(req.body); const event = await Event.create({ ...input, organizer: req.user!.id }); res.status(201).json({ data: event, error: null }) } catch (error) { next(error) } })
app.patch('/api/events/:id', auth, requireRole('Admin', 'Organizer'), async (req: AuthRequest, res, next) => { try { const event = await Event.findOneAndUpdate({ _id: req.params.id, ...(req.user!.role === 'Admin' ? {} : { organizer: req.user!.id }) }, req.body, { new: true, runValidators: true }); if (!event) return res.status(404).json({ data: null, error: 'Event not found' }); res.json({ data: event, error: null }) } catch (error) { next(error) } })
app.use((error: any, _req: Request, res: Response, _next: NextFunction) => { if (error instanceof z.ZodError) return res.status(400).json({ data: null, error: error.issues[0]?.message ?? 'Invalid request' }); console.error(error); res.status(500).json({ data: null, error: 'Internal server error' }) })

export const connectDatabase = async () => { if (process.env.MONGODB_URI && mongoose.connection.readyState !== 1) await mongoose.connect(process.env.MONGODB_URI) }

const start = async () => { await connectDatabase(); const server = app.listen(port, () => console.log(`EventSphere API listening on ${port}`)); const shutdown = async () => { await mongoose.connection.close(); server.close(() => process.exit(0)) }; process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown) }

if (!process.env.VERCEL) start().catch((error) => { console.error(error); process.exit(1) })

export default app
