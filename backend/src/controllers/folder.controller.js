import Folder from "../models/folder.model.js";
import User from "../models/user.model.js";
import File from "../models/file.model.js";
import mongoose from "mongoose";
import { deleteFiles } from "../services/minioOperations.js";
import { getFolderPathHierarchy, updateFolderChildReferences } from "../services/folderUtils.js";

const checkFolderAccess = async (folderId, userId, requiredPermission) => {
    try {
        const folder = await Folder.findById(folderId).populate('owner sharedWith.user');
        if (!folder) {
            return { hasAccess: false, folder: null, message: 'Folder not found.' };
        }
        
        if (folder.owner._id.toString() === userId) {
            return { hasAccess: true, folder, permission: 'manage' };
        }

        if (folder.visibility === 'public' && requiredPermission === 'view') {
            return { hasAccess: true, folder, permission: 'view' };
        }

        if (folder.visibility === 'protected') {
            const sharedEntry = folder.sharedWith.find(
                (entry) => entry.user && entry.user._id.toString() === userId
            );

            if (sharedEntry) {
                const userPermission = sharedEntry.permission;
                const permissionsOrder = ['view', 'edit', 'manage'];

                if (permissionsOrder.indexOf(userPermission) >= permissionsOrder.indexOf(requiredPermission)) {
                    return { hasAccess: true, folder, permission: userPermission };
                }
            }
        }

        return { hasAccess: false, folder, message: 'Access denied: Insufficient permissions.' };

    } catch (error) {
        console.error('Error checking folder access:', error);
        return { hasAccess: false, folder: null, message: 'Server error during access check.' };
    }
};

const createFolder = async (req, res) => {
    const { name="newfolder", parentFolderId, visibility, description, tags } = req.body;
    const ownerId = req.user.id;

    if (!name) {
        return res.status(400).json({ message: 'Folder name is required.' });
    }

    let parentFolder = null;

    if (parentFolderId) {
        const { hasAccess, folder: foundParentFolder, permission } = await checkFolderAccess(parentFolderId, ownerId, 'edit');
        if (!hasAccess || !foundParentFolder || (permission !== 'edit' && permission !== 'manage')) {
            return res.status(403).json({ message: 'Cannot create folder: Parent folder not found or insufficient permissions in parent.' });
        }
        if (foundParentFolder.isTrashed) {
            return res.status(400).json({ message: 'Cannot create folder in a trashed parent folder.' });
        }
        parentFolder = foundParentFolder;
    } else {
        // 🚫 Only allow one root-level folder per user
        const existingRoot = await Folder.findOne({ owner: ownerId, parentFolder: null, isTrashed: false });
        if (existingRoot) {
            return res.status(400).json({ message: 'Only one root-level folder is allowed per user.' });
        }
    }


    try {
        const duplicateFolder = await Folder.findOne({
            name,
            owner: ownerId,
            parentFolder: parentFolderId || null,
            isTrashed: false
        });

        if (duplicateFolder) {
            return res.status(409).json({ message: `A folder with the name '${name}' already exists in this location.` });
        }

        const newFolder = new Folder({
            name,
            owner: ownerId,
            parentFolder: parentFolderId || null,
            visibility: visibility || 'private',
            description: description || '',
            tags: tags || [],
        });

        

        await newFolder.save();

        if (parentFolderId) {
            await updateFolderChildReferences(parentFolderId, newFolder._id, 'folder', 'add');
        }
        
        res.status(201).json(newFolder);

    } catch (error) {
    
        console.error('Error creating folder:', error);
        res.status(500).json({ message: 'Server error while creating folder.', error: error.message });
    } 
};

const deleteFolder = async (req, res) => {
    const folderId = req.params.folderId;
    const userId = req.user.id;

    try{
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'manage');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }
        if (permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to delete this folder.' });
        }
        if (folder.isRoot) {
            return res.status(400).json({ message: 'Cannot delete the root folder.' });
        }

        // Use an aggregation pipeline to find all nested folders
        const aggregation = await Folder.aggregate([
            { $match: { _id: new mongoose.Types.ObjectId(folderId) } },
            {
                $graphLookup: {
                    from: 'folders',
                    startWith: '$_id',
                    connectFromField: '_id',
                    connectToField: 'parentFolder',
                    as: 'descendants',
                }
            },
            {
                $project: {
                    allFolderIds: {
                        $concatArrays: [["$_id"], "$descendants._id"]
                    }
                }
            }
        ]);

        if (aggregation.length === 0) {
            // This case should ideally not be hit if checkFolderAccess passed, but it's a good safeguard.
            return res.status(404).json({ message: 'Folder hierarchy not found.' });
        }

        const { allFolderIds } = aggregation[0];

        // Soft-delete all folders and files in one go by setting isTrashed to true
        await Folder.updateMany({ _id: { $in: allFolderIds } }, { $set: { isTrashed: true, trashedAt: new Date() } });
        await File.updateMany({ parentFolder: { $in: allFolderIds } }, { $set: { isTrashed: true, trashedAt: new Date() } });

        res.status(200).json({ message: 'Folder and its contents moved to trash successfully.' });

    } catch (error) {
        console.error('Error deleting folder:', error);
        res.status(500).json({ message: 'Server error while deleting folder.', error: error.message });
    }
}

const permanentlyDeleteFolder = async (req, res) => {
    const { folderId } = req.params;
    const userId = req.user._id.toString();

    try {
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'manage');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }
        if (permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to permanently delete this folder.' });
        }
        if (folder.isRoot) {
            return res.status(400).json({ message: 'The root folder cannot be permanently deleted.' });
        }

        const aggregation = await Folder.aggregate([
            { $match: { _id: new mongoose.Types.ObjectId(folderId) } },
            { $graphLookup: { from: 'folders', startWith: '$_id', connectFromField: '_id', connectToField: 'parentFolder', as: 'descendants' } },
            { $project: { allFolderIds: { $concatArrays: [["$_id"], "$descendants._id"] } } }
        ]);

        if (aggregation.length === 0) {
            return res.status(404).json({ message: 'Folder hierarchy not found.' });
        }
        const { allFolderIds } = aggregation[0];

        const filesToDelete = await File.find({ parentFolder: { $in: allFolderIds } }).select('fileObjectName size');
        const fileKeysToDelete = filesToDelete.map(file => file.fileObjectName);
        if (fileKeysToDelete.length > 0) {
            await deleteFiles(undefined, fileKeysToDelete);
        }

        const totalSizeDeleted = filesToDelete.reduce((sum, file) => sum + file.size, 0);
        const fileIdsToDelete = filesToDelete.map(file => file._id);
        const originalParentId = folder.parentFolder;

        await Promise.all([
            File.deleteMany({ _id: { $in: fileIdsToDelete } }),
            Folder.deleteMany({ _id: { $in: allFolderIds } }),
            User.findByIdAndUpdate(userId, { $inc: { storageUsed: -totalSizeDeleted } }),
            updateFolderChildReferences(originalParentId, folderId, 'folder', 'remove')
        ]);

        res.status(200).json({ message: 'Folder and its contents permanently deleted successfully.' });
    } catch (error) {
        console.error('Error permanently deleting folder:', error);
        res.status(500).json({ message: 'Server error while permanently deleting folder.', error: error.message });
    }    
}

const getFolderById = async (req, res) => {
   const { folderId } = req.params;
    const userId = req.user._id.toString();

    try {
        const { hasAccess, folder } = await checkFolderAccess(folderId, userId, 'view');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        res.status(200).json(folder);
    } catch (error) {
        console.error('Error getting folder:', error);
        res.status(500).json({ message: 'Server error while getting folder.', error: error.message });
    }
}

const getFolderContents = async (req, res) => {
    const { folderId } = req.params;
    const userId = req.user._id.toString();

    try {
        const { hasAccess, folder } = await checkFolderAccess(folderId, userId, 'view');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        const subfolders = await Folder.find({ parentFolder: folderId, isTrashed: false }).select('name owner createdAt updatedAt isStarred');
        const files = await File.find({ parentFolder: folderId, isTrashed: false }).select('filename mimetype size owner createdAt updatedAt isStarred');

        res.status(200).json({
            folder,
            contents: {
                subfolders,
                files
            }
        });
    } catch (error) {
        console.error('Error getting folder contents:', error);
        res.status(500).json({ message: 'Server error while getting folder contents.', error: error.message });
    }
};

const updateFolderDetails = async (req, res) => {
    const { folderId } = req.params;
    const userId = req.user._id.toString();
    const { name, description, tags, visibility } = req.body;

    // Ensure at least one field is being updated
    if (name === undefined && description === undefined && tags === undefined && visibility === undefined) {
        return res.status(400).json({ message: 'No update data provided.' });
    }

    try {
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'edit');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        if (permission !== 'edit' && permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to update this folder.' });
        }

        if (folder.isRoot && name) {
            return res.status(400).json({ message: 'The root folder cannot be renamed.' });
        }

        // Handle rename and check for duplicates in the same directory
        if (name && name !== folder.name) {
            const duplicateFolder = await Folder.findOne({
                _id: { $ne: folderId },
                name,
                parentFolder: folder.parentFolder,
                owner: folder.owner,
                isTrashed: false
            });

            if (duplicateFolder) {
                return res.status(409).json({ message: `A folder with the name '${name}' already exists in this location.` });
            }
            folder.name = name;
        }

        if (description !== undefined) folder.description = description;
        if (tags !== undefined) folder.tags = tags;
        if (visibility !== undefined) folder.visibility = visibility;

        const updatedFolder = await folder.save();
        res.status(200).json(updatedFolder);
    } catch (error) {
        console.error('Error updating folder details:', error);
        res.status(500).json({ message: 'Server error while updating folder details.', error: error.message });
    }
};

const moveFolder = async (req, res) => {
    const { folderId } = req.params;
    const { newParentFolderId } = req.body;
    const userId = req.user._id.toString();

    // 1. Basic validation
    if (!newParentFolderId) {
        return res.status(400).json({ message: 'A destination folder ID is required.' });
    }
    if (folderId === newParentFolderId) {
        return res.status(400).json({ message: 'Cannot move a folder into itself.' });
    }

    try {
        // 2. Fetch folders and check permissions in parallel for efficiency
        const [sourceCheck, destCheck] = await Promise.all([
            checkFolderAccess(folderId, userId, 'manage'),
            checkFolderAccess(newParentFolderId, userId, 'edit')
        ]);

        const { hasAccess: sourceAccess, folder: sourceFolder, permission: sourcePermission } = sourceCheck;
        const { hasAccess: destAccess, folder: destinationFolder, permission: destPermission } = destCheck;

        // 3. Validate source folder
        if (!sourceAccess || !sourceFolder) {
            return res.status(404).json({ message: 'Source folder not found or access denied.' });
        }
        if (sourcePermission !== 'manage') {
            return res.status(403).json({ message: 'You do not have permission to move this folder.' });
        }
        if (sourceFolder.isRoot) {
            return res.status(400).json({ message: 'The root folder cannot be moved.' });
        }
        if (sourceFolder.parentFolder && sourceFolder.parentFolder.toString() === newParentFolderId) {
            return res.status(200).json({ message: 'Folder is already in the destination.', folder: sourceFolder });
        }

        // 4. Validate destination folder
        if (!destAccess || !destinationFolder) {
            return res.status(404).json({ message: 'Destination folder not found or access denied.' });
        }
        if (destPermission !== 'edit' && destPermission !== 'manage') {
            return res.status(403).json({ message: 'You do not have permission to move items into the destination folder.' });
        }
        if (destinationFolder.isTrashed) {
            return res.status(400).json({ message: 'Cannot move a folder into a trashed folder.' });
        }

        // 5. Circular dependency check: A folder cannot be moved into its own descendant.
        const aggregation = await Folder.aggregate([
            { $match: { _id: new mongoose.Types.ObjectId(folderId) } },
            {
                $graphLookup: {
                    from: 'folders',
                    startWith: '$_id',
                    connectFromField: '_id',
                    connectToField: 'parentFolder',
                    as: 'descendants'
                }
            }
        ]);
        const descendantIds = aggregation[0]?.descendants.map(d => d._id.toString()) || [];
        if (descendantIds.includes(newParentFolderId)) {
            return res.status(400).json({ message: 'Invalid move: Cannot move a folder into one of its own subfolders.' });
        }

        // 6. Name conflict check in the destination
        const nameConflict = await Folder.findOne({
            _id: { $ne: folderId },
            name: sourceFolder.name,
            parentFolder: newParentFolderId,
            isTrashed: false
        }).lean();

        if (nameConflict) {
            return res.status(409).json({ message: `A folder named '${sourceFolder.name}' already exists in the destination.` });
        }

        // 7. Perform the move
        const originalParentId = sourceFolder.parentFolder;
        sourceFolder.parentFolder = new mongoose.Types.ObjectId(newParentFolderId);
        
        await Promise.all([
            sourceFolder.save(),
            updateFolderChildReferences(newParentFolderId, folderId, 'folder', 'add'),
            updateFolderChildReferences(originalParentId, folderId, 'folder', 'remove')
        ]);

        res.status(200).json({ message: 'Folder moved successfully.', folder: sourceFolder });
    } catch (error) {
        console.error('Error moving folder:', error);
        res.status(500).json({ message: 'Server error while moving folder.', error: error.message });
    }
};

const getUserRootFolder = async (req, res) => {
    const userId = req.user._id.toString();

    try {
        if (!req.user.rootFolder) {
            return res.status(404).json({ message: 'Root folder not found for this user.' });
        }

        const rootFolderId = req.user.rootFolder.toString();
        const folder = await Folder.findById(rootFolderId);

        if (!folder) {
            return res.status(404).json({ message: 'Root folder data is missing. This may indicate a data inconsistency.' });
        }

        const subfolders = await Folder.find({ parentFolder: rootFolderId, isTrashed: false }).select('name owner createdAt updatedAt isStarred');
        const files = await File.find({ parentFolder: rootFolderId, isTrashed: false }).select('filename mimetype size owner createdAt updatedAt isStarred');

        res.status(200).json({
            folder,
            contents: {
                subfolders,
                files
            }
        });
    } catch (error) {
        console.error('Error getting user root folder:', error);
        res.status(500).json({ message: 'Server error while getting root folder.', error: error.message });
    }
};

const getFolderBreadcrumbs = async (req, res) => {
    const { folderId } = req.params;
    const userId = req.user._id.toString();

    try {
        // 1. Check access to the starting folder. This also fetches the folder.
        const { hasAccess, folder } = await checkFolderAccess(folderId, userId, 'view');
        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        const breadcrumbs = [];
        let currentFolderId = folder._id;

        // 2. Traverse up the hierarchy to the root
        while (currentFolderId) {
            // Using .lean() for better performance as we only need to read data.
            const currentFolder = await Folder.findById(currentFolderId).select('_id name parentFolder').lean();

            if (!currentFolder) {
                // This indicates a data integrity issue, like a broken parent link.
                console.warn(`Breadcrumb traversal broke: could not find folder with ID ${currentFolderId}`);
                break;
            }

            breadcrumbs.unshift({ _id: currentFolder._id, name: currentFolder.name });
            currentFolderId = currentFolder.parentFolder;
        }

        res.status(200).json(breadcrumbs);
    } catch (error) {
        console.error('Error getting folder breadcrumbs:', error);
        res.status(500).json({ message: 'Server error while getting folder breadcrumbs.', error: error.message });
    }
};

const getTrashedItems = async (req, res) => {
    const userId = req.user._id.toString();

    try {
        // Find all folders and files owned by the user that are marked as trashed
        const trashedFolders = await Folder.find({ owner: userId, isTrashed: true })
            .select('name owner createdAt updatedAt trashedAt parentFolder')
            .lean();

        const trashedFiles = await File.find({ owner: userId, isTrashed: true })
            .select('filename mimetype size owner createdAt updatedAt trashedAt parentFolder')
            .lean();

        res.status(200).json({
            folders: trashedFolders,
            files: trashedFiles
        });
    } catch (error) {
        console.error('Error getting trashed items:', error);
        res.status(500).json({ message: 'Server error while getting trashed items.', error: error.message });
    }
};

const restoreFolder = async (req, res) => {
    const { folderId } = req.params;
    const userId = req.user._id.toString();

    try {
        // 1. Check access and that the folder is indeed trashed.
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'manage');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }
        if (permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to restore this folder.' });
        }
        if (!folder.isTrashed) {
            return res.status(400).json({ message: 'This folder is not in the trash.' });
        }

        // 2. Determine the destination folder. If the original parent is trashed or deleted, move to root.
        let destinationParentId = folder.parentFolder;
        if (destinationParentId) {
            const parentIsRestorable = await Folder.findOne({ _id: destinationParentId, isTrashed: false }).lean();
            if (!parentIsRestorable) {
                destinationParentId = req.user.rootFolder;
            }
        } else {
            // This should only be a root folder (which can't be trashed), but as a safeguard:
            destinationParentId = req.user.rootFolder;
        }

        if (!destinationParentId) {
            return res.status(500).json({ message: 'Could not find a valid destination to restore the folder to (root folder may be missing).' });
        }

        // 3. Check for name conflicts in the destination and rename if necessary.
        let finalFolderName = folder.name;
        const conflict = await Folder.findOne({
            name: finalFolderName,
            parentFolder: destinationParentId,
            isTrashed: false
        }).lean();

        if (conflict) {
            finalFolderName = `${folder.name} (restored ${Date.now()})`;
        }

        // 4. Find all descendant folders and files to restore using an aggregation pipeline.
        const aggregation = await Folder.aggregate([
            { $match: { _id: new mongoose.Types.ObjectId(folderId) } },
            {
                $graphLookup: {
                    from: 'folders',
                    startWith: '$_id',
                    connectFromField: '_id',
                    connectToField: 'parentFolder',
                    as: 'descendants'
                }
            },
            { $project: { allFolderIds: { $concatArrays: [["$_id"], "$descendants._id"] } } }
        ]);

        if (aggregation.length === 0) {
            return res.status(404).json({ message: 'Folder hierarchy not found.' });
        }
        const { allFolderIds } = aggregation[0];

        // 5. Perform the restoration.
        await Folder.updateMany({ _id: { $in: allFolderIds } }, { $set: { isTrashed: false }, $unset: { trashedAt: 1 } });
        await File.updateMany({ parentFolder: { $in: allFolderIds } }, { $set: { isTrashed: false }, $unset: { trashedAt: 1 } });

        // Update the top-level folder's name and location if it changed.
        await Folder.updateOne({ _id: folderId }, { $set: { parentFolder: destinationParentId, name: finalFolderName } });

        res.status(200).json({ message: `Folder '${finalFolderName}' and its contents have been restored.` });
    } catch (error) {
        console.error('Error restoring folder:', error);
        res.status(500).json({ message: 'Server error while restoring folder.', error: error.message });
    }
};

const emptyTrash = async (req, res) => {
    const userId = req.user._id.toString();

    try {
        // 1. Find all trashed items for the user to get their IDs and necessary info
        const trashedFolders = await Folder.find({ owner: userId, isTrashed: true }).select('_id').lean();
        const trashedFiles = await File.find({ owner: userId, isTrashed: true }).select('_id fileObjectName size').lean();

        if (trashedFolders.length === 0 && trashedFiles.length === 0) {
            return res.status(200).json({ message: 'Trash is already empty.' });
        }

        // 2. Collect all necessary data for deletion
        const folderIdsToDelete = trashedFolders.map(f => f._id);
        const fileIdsToDelete = trashedFiles.map(f => f._id);
        const fileKeysToDelete = trashedFiles.map(f => f.fileObjectName).filter(Boolean);
        const totalSizeDeleted = trashedFiles.reduce((sum, file) => sum + file.size, 0);

        // 3. Build an array of promises for all deletion and update operations
        const operations = [];

        if (fileKeysToDelete.length > 0) {
            operations.push(deleteFiles(undefined, fileKeysToDelete));
        }
        if (fileIdsToDelete.length > 0) {
            operations.push(File.deleteMany({ _id: { $in: fileIdsToDelete } }));
        }
        if (folderIdsToDelete.length > 0) {
            operations.push(Folder.deleteMany({ _id: { $in: folderIdsToDelete } }));
        }
        if (totalSizeDeleted > 0) {
            operations.push(User.findByIdAndUpdate(userId, { $inc: { storageUsed: -totalSizeDeleted } }));
        }

        await Promise.all(operations);

        res.status(200).json({ message: 'Trash has been emptied successfully.' });
    } catch (error) {
        console.error('Error emptying trash:', error);
        res.status(500).json({ message: 'Server error while emptying trash.', error: error.message });
    }
};

const updateFolderVisibility = async (req, res) => {
    const { folderId } = req.params;
    const { visibility } = req.body;
    const userId = req.user._id.toString();

    if (!visibility) {
        return res.status(400).json({ message: 'Visibility status is required.' });
    }

    const allowedVisibilities = ['private', 'protected', 'public'];
    if (!allowedVisibilities.includes(visibility)) {
        return res.status(400).json({ message: `Invalid visibility value. Must be one of: ${allowedVisibilities.join(', ')}` });
    }

    try {
        // For changing something as important as visibility, 'manage' permission is appropriate.
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'manage');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        if (permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to change folder visibility.' });
        }

        folder.visibility = visibility;
        const updatedFolder = await folder.save();

        res.status(200).json(updatedFolder);
    } catch (error) {
        console.error('Error updating folder visibility:', error);
        res.status(500).json({ message: 'Server error while updating folder visibility.', error: error.message });
    }
};

const shareFolder = async (req, res) => {
    const { folderId } = req.params;
    const { email, permission } = req.body; // Sharing via email is more user-friendly
    const ownerId = req.user._id.toString();

    // 1. Basic validation
    if (!email || !permission) {
        return res.status(400).json({ message: 'User email and a permission level are required.' });
    }

    const allowedPermissions = ['view', 'edit'];
    if (!allowedPermissions.includes(permission)) {
        return res.status(400).json({ message: `Invalid permission. Must be one of: ${allowedPermissions.join(', ')}` });
    }

    try {
        // 2. Check if the current user has 'manage' rights to the folder
        const { hasAccess, folder } = await checkFolderAccess(folderId, ownerId, 'manage');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or you do not have permission to share it.' });
        }

        // 3. Find the user to share with
        const userToShareWith = await User.findOne({ email }).select('_id');
        if (!userToShareWith) {
            return res.status(404).json({ message: `User with email '${email}' not found.` });
        }

        const shareWithUserId = userToShareWith._id.toString();

        // 4. Prevent sharing with the owner
        if (folder.owner._id.toString() === shareWithUserId) {
            return res.status(400).json({ message: 'You cannot share a folder with yourself (the owner).' });
        }

        // 5. Update the sharedWith array
        const existingShareIndex = folder.sharedWith.findIndex(
            (share) => share.user && share.user._id.toString() === shareWithUserId
        );

        if (existingShareIndex > -1) {
            // If user is already in the list, just update their permission
            folder.sharedWith[existingShareIndex].permission = permission;
        } else {
            // Otherwise, add the new user to the shared list
            folder.sharedWith.push({ user: shareWithUserId, permission });
        }

        // 6. If the folder was private, its visibility must be changed to 'protected' for sharing to take effect.
        if (folder.visibility === 'private') {
            folder.visibility = 'protected';
        }

        const savedFolder = await folder.save();

        await savedFolder.populate({ path: 'sharedWith.user', select: 'username email profile.avatar' });

        res.status(200).json({ message: 'Folder shared successfully.', folder: savedFolder });
    } catch (error) {
        console.error('Error sharing folder:', error);
        res.status(500).json({ message: 'Server error while sharing folder.', error: error.message });
    }
};

const unshareFolder = async (req, res) => {
    const { folderId } = req.params;
    const { userIdToUnshare } = req.body; // Unsharing by user ID is more direct and less ambiguous than email.
    const currentUserId = req.user._id.toString();

    // 1. Basic validation
    if (!userIdToUnshare) {
        return res.status(400).json({ message: 'User ID to unshare is required.' });
    }

    try {
        // 2. Check if the current user has 'manage' rights to the folder
        const { hasAccess, folder } = await checkFolderAccess(folderId, currentUserId, 'manage');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or you do not have permission to manage its sharing settings.' });
        }

        // 3. Prevent unsharing from the owner
        if (folder.owner._id.toString() === userIdToUnshare) {
            return res.status(400).json({ message: 'Cannot unshare the folder from its owner. The owner always has manage access.' });
        }

        // 4. Find the subdocument for the user to be unshared
        const shareEntry = folder.sharedWith.find(
            (share) => share.user && share.user._id.toString() === userIdToUnshare
        );

        if (!shareEntry) {
            return res.status(404).json({ message: 'This user is not in the folder\'s share list.' });
        }

        // 5. Remove the user from the sharedWith array using the subdocument's _id
        folder.sharedWith.pull(shareEntry._id);

        // 6. If the folder is 'protected' and no one else is shared with, revert its visibility to 'private'.
        if (folder.visibility === 'protected' && folder.sharedWith.length === 0) {
            folder.visibility = 'private';
        }

        const savedFolder = await folder.save();
        await savedFolder.populate({ path: 'sharedWith.user', select: 'username email profile.avatar' });

        res.status(200).json({ message: 'Folder unshared successfully.', folder: savedFolder });
    } catch (error) {
        console.error('Error unsharing folder:', error);
        res.status(500).json({ message: 'Server error while unsharing folder.', error: error.message });
    }
};

const updateSharedPermission = async (req, res) => {
    const { folderId } = req.params;
    const { userIdToUpdate, permission } = req.body;
    const currentUserId = req.user._id.toString();

    // 1. Basic validation
    if (!userIdToUpdate || !permission) {
        return res.status(400).json({ message: 'User ID and a permission level are required.' });
    }

    const allowedPermissions = ['view', 'edit'];
    if (!allowedPermissions.includes(permission)) {
        return res.status(400).json({ message: `Invalid permission. Must be one of: ${allowedPermissions.join(', ')}` });
    }

    try {
        // 2. Check if the current user has 'manage' rights to the folder
        const { hasAccess, folder } = await checkFolderAccess(folderId, currentUserId, 'manage');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or you do not have permission to manage its sharing settings.' });
        }

        // 3. Prevent updating the owner's permission
        if (folder.owner._id.toString() === userIdToUpdate) {
            return res.status(400).json({ message: 'Cannot change the owner\'s permission. The owner always has manage access.' });
        }

        // 4. Find the user in the sharedWith array and update their permission
        const shareEntry = folder.sharedWith.find(
            (share) => share.user && share.user._id.toString() === userIdToUpdate
        );

        if (!shareEntry) {
            return res.status(404).json({ message: 'This user is not in the folder\'s share list. Use the share endpoint to add them first.' });
        }

        // 5. Update the permission
        shareEntry.permission = permission;

        const savedFolder = await folder.save();
        await savedFolder.populate({ path: 'sharedWith.user', select: 'username email profile.avatar' });

        res.status(200).json({ message: 'Shared user permission updated successfully.', folder: savedFolder });
    } catch (error) {
        console.error('Error updating shared permission:', error);
        res.status(500).json({ message: 'Server error while updating shared permission.', error: a.message });
    }
};

const getSharedFolders = async (req, res) => {
    const userId = req.user._id.toString();

    try {
        // Find all folders where the current user's ID is present in the sharedWith array
        // and the folder is not in the trash.
        const sharedFolders = await Folder.find({
            'sharedWith.user': userId,
            isTrashed: false
        })
        .populate('owner', 'username email profile.avatar')
        .populate({
            path: 'sharedWith.user',
            select: 'username email profile.avatar'
        })
        .lean(); // Use .lean() for faster read-only operations

        res.status(200).json(sharedFolders);
    } catch (error) {
        console.error('Error getting shared folders:', error);
        res.status(500).json({ message: 'Server error while retrieving shared folders.', error: error.message });
    }
};

const toggleStarFolder = async (req, res) => {
    const { folderId } = req.params;
    const userId = req.user._id.toString();

    try {
        // To modify a folder property like 'isStarred', the user should have 'edit' permissions.
        // While starring is a personal preference, the current schema stores it on the folder itself,
        // making it a shared property.
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'edit');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        if (permission !== 'edit' && permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to star this folder.' });
        }

        folder.isStarred = !folder.isStarred;
        const updatedFolder = await folder.save();

        res.status(200).json({
            message: `Folder ${updatedFolder.isStarred ? 'starred' : 'unstarred'} successfully.`,
            folder: updatedFolder
        });

    } catch (error) {
        console.error('Error toggling star on folder:', error);
        res.status(500).json({ message: 'Server error while toggling star on folder.', error: error.message });
    }
};

const addFolderTags = async (req, res) => {
    const { folderId } = req.params;
    const { tags } = req.body; // Expecting an array of tags to add
    const userId = req.user._id.toString();

    if (!tags || !Array.isArray(tags) || tags.length === 0) {
        return res.status(400).json({ message: 'An array of tags to add is required.' });
    }

    try {
        // 'edit' permission should be sufficient to modify tags.
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'edit');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        if (permission !== 'edit' && permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to add tags to this folder.' });
        }

        // Use $addToSet with $each to add multiple tags to the array without creating duplicates.
        const updatedFolder = await Folder.findByIdAndUpdate(
            folderId,
            { $addToSet: { tags: { $each: tags } } },
            { new: true } // Return the updated document
        );

        res.status(200).json({ message: 'Tags added successfully.', folder: updatedFolder });

    } catch (error) {
        console.error('Error adding folder tags:', error);
        res.status(500).json({ message: 'Server error while adding folder tags.', error: error.message });
    }
};

const removeFolderTags = async (req, res) => {
    const { folderId } = req.params;
    const { tags } = req.body; // Expecting an array of tags to remove
    const userId = req.user._id.toString();

    if (!tags || !Array.isArray(tags) || tags.length === 0) {
        return res.status(400).json({ message: 'An array of tags to remove is required.' });
    }

    try {
        // 'edit' permission should be sufficient to modify tags.
        const { hasAccess, folder, permission } = await checkFolderAccess(folderId, userId, 'edit');

        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        if (permission !== 'edit' && permission !== 'manage') {
            return res.status(403).json({ message: 'Insufficient permissions to remove tags from this folder.' });
        }

        // Use $pullAll to remove all occurrences of the specified tags from the array.
        const updatedFolder = await Folder.findByIdAndUpdate(
            folderId,
            { $pullAll: { tags: tags } },
            { new: true } // Return the updated document
        );

        res.status(200).json({ message: 'Tags removed successfully.', folder: updatedFolder });

    } catch (error) {
        console.error('Error removing folder tags:', error);
        res.status(500).json({ message: 'Server error while removing folder tags.', error: error.message });
    }
};

const searchFolders = async (req, res) => {
     const { q, tags, visibility, owner, parentFolder, isStarred, isTrashed } = req.query;
    const userId = req.user._id;

    if (Object.keys(req.query).length === 0) {
        return res.status(400).json({ message: 'At least one search parameter is required.' });
    }

    try {
        // Clause 1: Access Control. The user must have access to the folder.
        const accessControlClause = {
            $or: [
                { owner: userId },
                { visibility: 'public' },
                { 'sharedWith.user': userId } // User is in the share list
            ]
        };

        const searchFilterClause = {  };

        if (q) {
            const searchRegex = { $regex: q, $options: 'i' };
            // Search in both name and description
            searchFilterClause.$or = [
                { name: searchRegex },
                { description: searchRegex }
            ];
        }

        if (tags) {
            const tagsArray = tags.split(',').map(tag => tag.trim()).filter(Boolean);
            if (tagsArray.length > 0) {
                searchFilterClause.tags = { $in: tagsArray };
            }
        }

        if (visibility) {
            const allowedVisibilities = ['private', 'protected', 'public'];
            if (allowedVisibilities.includes(visibility)) {
                searchFilterClause.visibility = visibility;
            }
        }

         // Owner filter
        if (owner) {
            if (!mongoose.Types.ObjectId.isValid(owner)) {
                return res.status(400).json({ message: 'Invalid owner ID format.' });
            }
            searchFilterClause.owner = owner;
        }

        // Parent folder filter
        if (parentFolder) {
            if (parentFolder === 'null') { // Handle search for root folders
                searchFilterClause.parentFolder = null;
            } else if (mongoose.Types.ObjectId.isValid(parentFolder)) {
                searchFilterClause.parentFolder = parentFolder;
            } else {
                return res.status(400).json({ message: 'Invalid parentFolder ID format.' });
            }
        }

        // Starred filter
        if (isStarred !== undefined) {
            searchFilterClause.isStarred = isStarred === 'true';
        }

        // Trashed filter - Default to searching non-trashed items unless specified
        if (isTrashed !== undefined) {
            searchFilterClause.isTrashed = isTrashed === 'true';
        } else {
            searchFilterClause.isTrashed = false;
        }

        // Combine clauses: user must have access AND the folder must match search filters.
        const finalQuery = { $and: [accessControlClause, searchFilterClause] };

        const folders = await Folder.find(finalQuery).populate('owner', 'username email profile.avatar').lean();

        res.status(200).json(folders);
    } catch (error) {
        console.error('Error searching folders:', error);
        res.status(500).json({ message: 'Server error while searching folders.', error: error.message });
    }
};

const getFolderPath = async (req, res) => {
    const { folderId } = req.params;
    const userId = req.user._id.toString();

    try {
        // 1. Check access to the starting folder.
        const { hasAccess, folder } = await checkFolderAccess(folderId, userId, 'view');
        if (!hasAccess || !folder) {
            return res.status(404).json({ message: 'Folder not found or access denied.' });
        }

        // 2. Get the folder hierarchy using the helper function.
        const hierarchy = await getFolderPathHierarchy(folder._id);

        // 3. Format the path string.
        const pathParts = hierarchy.map(f => f.name);
        const fullPath = '/' + pathParts.join('/');

        res.status(200).json({ path: fullPath, folderId: folder._id });
    } catch (error)
    {
        console.error('Error getting folder path:', error);
        res.status(500).json({ message: 'Server error while getting folder path.', error: error.message });
    }
};



export {
    createFolder,
    deleteFolder,
    permanentlyDeleteFolder,
    getFolderById,
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
    
}