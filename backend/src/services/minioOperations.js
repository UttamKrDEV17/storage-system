import fs from 'fs'
import { Upload } from '@aws-sdk/lib-storage'
import path from 'path';
import {s3Client } from "../config/minio.js"
import mime from 'mime-types'

const uploadFile = async (bucketName = process.env.MINIO_BUCKET,filePath) => {
  const fileStream = fs.createReadStream(filePath)
  const fileName = path.basename(filePath)

  const mimeType = mime.lookup(filePath) || 'application/octet-stream';

  const upload = new Upload({
    client: s3Client,
    params: {
      Bucket: bucketName,
      Key: fileName,
      Body: fileStream,
        ContentType: mimeType,
    },
    queueSize: 4,            
    partSize: 5 * 1024 * 1024,
    leavePartsOnError: false,
  })

  upload.on('httpUploadProgress', (progress) => {
    process.stdout.write(`\r Uploaded ${progress.loaded}/${progress.total} bytes`);
  })

  try {
    const result = await upload.done()
    console.log(`Upload complete`)
    return result;
  } catch (err) {
    console.error('Upload failed:', err)
  }
}

const deleteFiles = async (bucketName = process.env.MINIO_BUCKET, objectKeys) => {
  if (!objectKeys || objectKeys.length === 0) {
    return;
  }

  const deleteParams = {
    Bucket: bucketName,
    Delete: {
      Objects: objectKeys.map(key => ({ Key: key })),
      Quiet: false,
    },
  };

  try {
    const { Deleted, Errors } = await s3Client.deleteObjects(deleteParams);
    if (Deleted) {
      console.log(`Successfully deleted ${Deleted.length} objects from Minio.`);
    }
    if (Errors && Errors.length > 0) {
      console.error('Errors encountered during Minio deletion:', Errors);
    }
    return { Deleted, Errors };
  } catch (err) {
    console.error('Error deleting files from Minio:', err);
    throw err;
  }
};

export { 
    uploadFile,
    deleteFiles,
}