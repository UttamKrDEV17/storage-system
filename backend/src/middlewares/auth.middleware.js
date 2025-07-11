import jwt from 'jsonwebtoken';
import User from '../models/user.model.js'

export async function authenticateJWT(req,res,next){
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'Authorization header is missing.' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token format is invalid.' });
    }

    try{
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next(); 
    } catch (error) {
        console.error('JWT verification error:', error);
        return res.status(403).json({ message: 'Invalid or expired token.' });
    }
}

export async function authMiddleware (req, res, next) { 
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) { 
        return res.status(401).json({ message: 'No token, authorization denied.' });
    }
    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            return res.status(401).json({ message: 'Token is valid, but user not found.' });
        }

        if (user.accountStatus !== 'active') {
             return res.status(403).json({ message: `Account is ${user.accountStatus}. Please check your status.` });
        }
        if (!user.isEmailVerified) {
             return res.status(403).json({ message: 'Please verify your email address.' });
        }

        req.user = user; 

        next();
    } catch (error) {
        console.error('Auth middleware error:', error.message);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired. Please log in again.' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token. Authorization denied.' });
        }
        return res.status(500).json({ message: 'Server error during authentication.' });
    }
};