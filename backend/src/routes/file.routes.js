import express from 'express'
import {upload} from '../middlewares/multer.middleware.js'
import { uploadSingleFile } from '../controllers/file.controller.js';
import { authMiddleware } from '../middlewares/auth.middleware.js';

const router = express.Router()

//single fileUpload
router.post('/single',authMiddleware,upload.single('file'),uploadSingleFile)

//multiple fileUpload


export default router;