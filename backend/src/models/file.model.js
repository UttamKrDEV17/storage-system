import mongoose from 'mongoose';

const sharedAccessSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    permission: {
        type: String,
        enum: ['view', 'edit'],
        required: true,
    }
}, { _id: false });

const fileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: [true, 'Filename is required.'],
    trim: true,
  },
  fileObjectName: {
    type: String,
    required: true,
    unique: true,
  },
  mimetype: {
    type: String,
    required: true,
  },
  size: {
    type: Number, // In bytes
    required: true,
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  parentFolder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    required: true,
  },
  isStarred: {
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
  accessType: {
        type: String,
        enum: ['private', 'public', 'protected'], // 'protected' implies shared
        default: 'private', // Default to private for security
        required: true,
    },
  sharedWith: [sharedAccessSchema],
  views: {
    type: Number,
    default: 0,
  }
}, { timestamps: true });

fileSchema.index({ parentFolder: 1, filename: 1, owner: 1 }, { unique: true });

const File = mongoose.model('File', fileSchema);
export default File;