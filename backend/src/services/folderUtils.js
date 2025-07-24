import Folder from '../models/folder.model.js';

/**
 * A helper function to add or remove child references from a parent folder's arrays.
 * @param {import('mongoose').Types.ObjectId | string | null} parentId - The ID of the parent folder.
 * @param {import('mongoose').Types.ObjectId | string} childId - The ID of the child item (folder or file).
 * @param {'folder' | 'file'} childType - The type of the child item.
 * @param {'add' | 'remove'} operation - The operation to perform.
 */
export const updateFolderChildReferences = async (parentId, childId, childType, operation) => {
    if (!parentId) {
        return; // Nothing to do if there's no parent
    }

    const updateField = childType === 'folder' ? 'childFolders' : 'childFiles';
    const updateOperation = operation === 'add' ? '$addToSet' : '$pull';

    try {
        await Folder.findByIdAndUpdate(parentId, {
            [updateOperation]: { [updateField]: childId }
        });
    } catch (error) {
        // Log the error but don't re-throw, as this is a background-like task.
        // The main controller function will handle the overall transaction failure.
        console.error(`Failed to ${operation} child reference for ${childType} ${childId} in parent ${parentId}:`, error);
    }
};

/**
 * Traverses up the folder hierarchy from a starting folder to the root.
 * @param {import('mongoose').Types.ObjectId} startFolderId - The ID of the folder to start from.
 * @returns {Promise<Array<Object>>} A promise that resolves to an array of folder objects representing the path.
 */
export const getFolderPathHierarchy = async (startFolderId) => {
    const hierarchy = [];
    let currentFolderId = startFolderId;

    while (currentFolderId) {
        // Using .lean() for better performance as we only need to read data.
        const currentFolder = await Folder.findById(currentFolderId).select('_id name parentFolder').lean();

        if (!currentFolder) {
            // This indicates a data integrity issue, like a broken parent link.
            console.warn(`Path traversal broke: could not find folder with ID ${currentFolderId}`);
            break;
        }

        hierarchy.unshift(currentFolder);
        currentFolderId = currentFolder.parentFolder;
    }
    return hierarchy;
};

