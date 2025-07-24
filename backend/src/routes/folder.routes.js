import express from "express"
import { createFolder,
      deleteFolder,
      getFolderById, 
      permanentlyDeleteFolder, 
      getFolderContents, 
      updateFolderDetails, 
      moveFolder,
      getUserRootFolder,
      getFolderBreadcrumbs,
      getTrashedItems,
      restoreFolder,
      emptyTrash,
      updateFolderVisibility,
      shareFolder,
      unshareFolder,
      updateSharedPermission,
      getSharedFolders,
      toggleStarFolder,
      addFolderTags,
      removeFolderTags,
      searchFolders,
      getFolderPath,
    } from "../controllers/folder.controller.js"
import { authMiddleware } from "../middlewares/auth.middleware.js"

const router = express.Router()


router.get("/root", authMiddleware, getUserRootFolder)
router.get("/trash", authMiddleware, getTrashedItems)
router.get("/:folderId", authMiddleware, getFolderById)
router.get("/:folderId/contents", authMiddleware, getFolderContents)
router.get("/:folderId/breadcrumbs", authMiddleware, getFolderBreadcrumbs)
router.get("/:folderId/shared", authMiddleware, getSharedFolders)
router.get("/search", authMiddleware, searchFolders)
router.get("/:folderId/path", authMiddleware, getFolderPath)
router.post("/createfolder", authMiddleware, createFolder)
router.post("/:folderId/share", authMiddleware, shareFolder)
router.post("/:folderId/unshare", authMiddleware, unshareFolder)
router.patch("/:folderId", authMiddleware, updateFolderDetails)
router.patch("/:folderId/move", authMiddleware, moveFolder)
router.patch("/:folderId/restore", authMiddleware, restoreFolder)
router.patch("/:folderId/visibility", authMiddleware, updateFolderVisibility)
router.patch("/:folderId/permission", authMiddleware, updateSharedPermission)
router.patch("/:folderId/star", authMiddleware, toggleStarFolder)
router.patch("/:folderId/tags/add", authMiddleware, addFolderTags)
router.patch("/:folderId/tags/remove", authMiddleware, removeFolderTags)
router.delete("/trash/empty", authMiddleware, emptyTrash)
router.delete("/:folderId", authMiddleware, deleteFolder)
router.delete("/permanent/:folderId", authMiddleware, permanentlyDeleteFolder)


export default router