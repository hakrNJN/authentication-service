import { Router } from 'express';
// --- Import specific feature routers below ---
import authRouter from './auth.routes'; // Authentication routes
import systemRouter from './system.routes'; // System routes (health, info)

const router = Router();

// --- Register feature routers here ---
router.use('/auth', authRouter); // Mount auth routes under /api/auth
router.use('/system', systemRouter); // Mount system routes under /api/system

// Default route for /api removed as specific routes cover functionality

export default router;

