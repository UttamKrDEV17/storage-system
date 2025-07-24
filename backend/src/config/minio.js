import * as Minio from "minio";
import { S3Client } from '@aws-sdk/client-s3'


// Setup MinIO credentials (S3-compatible)
const s3Client = new S3Client({
  endpoint:  process.env.MINIO_ENDPOINT,     
  region: process.env.MINIO_DEFAULT_REGION,                   
  credentials: {
    accessKeyId: process.env.MINIO_ACCESS_KEY,                
    secretAccessKey: process.env.MINIO_SECRET_KEY,         
  },
  forcePathStyle: true,             
})



export {
  s3Client
}