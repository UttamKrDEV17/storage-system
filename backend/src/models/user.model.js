import mongoose from 'mongoose';

const addressSchema = new mongoose.Schema({
    street: {
        type: String,
        trim: true,
    },
    city: {
        type: String,
        trim: true,
    },
    state: {
        type: String,
        trim: true,
    },
    postalCode: {
        type: String,
        trim: true,
    }
},{_id: false});


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters long'],
        maxlength: [30,'Username cannot exceed 30 characters'],
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        match: [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Please fill a valid email address'],
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        select: false,
    },
    passwordChangedAt: { // NEW: Timestamp for last password change
        type: Date,
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
    profile: {
        firstname: {
            type: String,
            trim: true,
        },
        lastname: {
            type: String,
            trim: true,
        },
        birthdate: {
            type: Date,
        },
        avatar: {
            type: String,
        },
        bio: {
            type: String,
            trim: true,
            maxlength: [500,"Bio cannot exceed 500 characters"],
        },
        gender: {
            type: String,
            enum: ['male', 'female', 'other', 'prefer_not_to_say'],
        },
        phone: { // NEW: Phone number
            type: String,
            trim: true,
        },
    },
    addresses: [addressSchema],
    accountStatus: { // NEW: More granular account status
        type: String,
        enum: ['active', 'pending_email_verification', 'suspended', 'locked', 'deactivated'],
        default: 'pending_email_verification', // Or 'active' if email verification is not mandatory at signup
    },
    lastLogin: {
        type: Date,
        default: null,
    },
    lastLoginIp: { // NEW: IP address of last login
        type: String,
    },
    lastLoginUserAgent: { // NEW: User Agent of last login
        type: String,
        trim: true,
    },
    lastLogout: {
        type: Date,
        default: null,
    },
    resetPasswordToken: {
        type: String,
        default: null,
    },
    resetPasswordExpires: {
        type: Date,
        default: null,
    },
    isEmailVerified: {
        type: Boolean,
        default: false,
    },
    emailVerificationToken: {
        type: String,
        default: null,
    },
    emailVerificationExpires: {
        type: Date,
        default: null,
    },
    is2FAEnabled: { // NEW: Two-Factor Authentication status
        type: Boolean,
        default: false,
    },
    twoFASecret: { // NEW: Two-Factor Authentication secret
        type: String,
        select: false,
    },
    storageUsed: {
        type: Number,
        default: 0, // In bytes
    },
    storageQuota: {
        type: Number,
        default: 15 * 1024 * 1024 * 1024, // Default 15 GB in bytes
    },
    rootFolder: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Folder',
    },
    adminNotes: { // NEW: For internal admin notes
        type: String,
        trim: true,
    },
    deactivationReason: { // NEW: Reason if account is deactivated
        type: String,
        trim: true,
    },
    deactivatedAt: { // NEW: Timestamp of deactivation
        type: Date,
    },
},{timestamps: true});

export default mongoose.model('User', userSchema);