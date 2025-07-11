import mongoose from 'mongoose';

const sharedAccessSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    permission: {
        type: String,
        enum: ['view', 'edit', 'manage'], // Added 'manage' for folders
        required: true,
    }
}, { _id: false });

const folderSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Folder name is required.'],
        trim: true,
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    parentFolder: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Folder',
        default: null, // null indicates a root-level folder for the user
    },
    childFolders: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Folder',
    }],
    childFiles: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'File',
    }],
    isRoot: {
        type: Boolean,
        default: false, // Special flag for the user's main root folder
    },
    isStarred: { // NEW: Starred folder
        type: Boolean,
        default: false,
    },
    isTrashed: {
        type: Boolean,
        default: false,
    },
    trashedAt: {
        type: Date,
        default: null,
    },
    deletedBy: { // NEW: Who trashed it
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null,
    },
    originalParentFolder: { // NEW: For easier restoration
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Folder',
        default: null,
    },
    visibility: { // NEW: Visibility for folders
        type: String,
        enum: ['private', 'public', 'protected'],
        required: true,
        default: 'private',
    },
    sharedWith: [sharedAccessSchema], // NEW: Shared access for 'protected' folders
    // cachedSize: { // OPTIONAL: Total size of contents. Requires complex updates.
    //     type: Number,
    //     default: 0,
    // },
    description: { // OPTIONAL: Folder description
        type: String,
        trim: true,
    },
    tags: [{ // OPTIONAL: Tags for organization
        type: String,
        trim: true,
    }],
}, { timestamps: true });

folderSchema.index({ parentFolder: 1, name: 1, owner: 1 }, { unique: true });

// Optional: Index to enforce only one primary root folder per user
folderSchema.index({ owner: 1, isRoot: 1 }, { unique: true, partialFilterExpression: { isRoot: true } });

const Folder = mongoose.model('Folder', folderSchema);
export default Folder;