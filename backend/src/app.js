import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';


const app = express();
app.use(cors());
app.use(helmet());
app.use(morgan('combined'));
app.use(express.json());


export default app;