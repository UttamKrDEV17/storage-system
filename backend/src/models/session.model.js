import mongoose from "mongoose";

const sessionSchema= new mongoose.Schema({
    token: {
        type: String,
        required: [true, 'Token is required'],
        unique: true,
        trim: true,
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User is required'],
    },
    expiresAt: {
        type: Date,
        required: [true, 'Expiration date is required'],
    },    
    isRevoked: {
        type: Boolean,
        default: false,
    },
    ipAddress: {
        type: String,
    },
    userAgent: {
        type: String,
    },
},{timestamps: true});

export default mongoose.model('Session', sessionSchema);