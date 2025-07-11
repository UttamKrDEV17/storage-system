import express from 'express';
import { login, refresh, register, logout, logoutAll, forgotPassword, resetPassword ,sendVerificationEmail, verifyEmail} from '../controllers/auth.controller.js';
import { authMiddleware } from '../middlewares/auth.middleware.js';

const router = express.Router();

router.post('/login', login);
router.post('/register', register);
router.post('/refresh', refresh);
router.post('/logout',authMiddleware, logout);
router.post('/logout-all',authMiddleware, logoutAll);
router.post('/forgot-password', forgotPassword); 
router.post('/reset-password', resetPassword);  
router.post('/send-verification', sendVerificationEmail); 
router.get('/verify-email', verifyEmail);              

export default router;