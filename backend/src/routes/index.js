import express from "express"
const router = express.Router()

import authRoutes from './auth.routes.js';
import fileRoutes from './file.routes.js';
import folderRoutes from './folder.routes.js'

router.use('/auth',authRoutes);
router.use('/upload',fileRoutes);
router.use('/folder',folderRoutes);

export default router