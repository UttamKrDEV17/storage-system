import fs from "fs";
import File from "../models/file.model.js";
import Folder from "../models/folder.model.js";
import User from "../models/user.model.js";
import { uploadFile } from "../services/minioOperations.js";
import { updateFolderChildReferences } from "../services/folderUtils.js";

const uploadSingleFile = async (req, res) => {
  const file = req.file;
  const userId = req.user._id;

  if (!file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    let parentFolderId = req.body.parentFolderId;

    if (!parentFolderId){
      const user = await User.findById(userId).select("rootFolder");
      if(!user || !user.rootFolder){
        return res.status(400).json({error:"Root folder not found for user"})
      } 
      parentFolderId = user.rootFolder;
      if (user.storageUsed + file.size > user.storageQuota) {
        fs.unlink(file.path);
        return res.status(403).json({ error: "Storage quota exceeded" });
      }
    }
     const folder = await Folder.findOne({ _id: parentFolderId, owner: userId });
    if (!folder) {
      return res.status(404).json({ error: "Parent folder not found or access denied" });
    }

    let newFilename = file.originalname;
    let counter = 0;
    let filenameExists = true;

    while (filenameExists) {
      const existingFile = await File.findOne({
        filename: newFilename,
        parentFolder: parentFolderId,
        owner: userId,
      });

      if (existingFile) {
        counter++;
        const parts = file.originalname.split('.');
        const extension = parts.pop();
        const baseName = parts.join('.'); 

        newFilename = `${baseName} (${counter}).${extension}`;
      } else {
        filenameExists = false;
      }
    }


    const etag = await uploadFile(undefined,file.path);

    const fileDoc = await File.create({
      filename: newFilename,
      fileObjectName: etag.Key,
      mimetype: file.mimetype,
      size: file.size,
      owner: userId,
      parentFolder: parentFolderId,
      accessType: req.body.accessType || "private",
    });

    await updateFolderChildReferences(parentFolderId, fileDoc._id, 'file', 'add');

    await User.findByIdAndUpdate(userId, {
      $inc: { storageUsed: file.size }
    });

    fs.unlink(file.path, (err) => {
      if (err) console.error("Failed to delete temp file:", err);
    });

    res.status(201).json({
      message: "File uploaded successfully",
      file: fileDoc,
    });

  } catch (err) {
    console.error("Upload failed:", err.message);
    fs.unlink(file.path, (err) => {
      if (err) console.error("Failed to delete temp file:", err);
    });

    res.status(500).json({ error: err.message });
  }
};



export { uploadSingleFile };
