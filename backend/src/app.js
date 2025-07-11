import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import authRoutes from './routes/auth.routes.js';

const app = express();
app.use(cors());
app.use(helmet());
app.use(morgan('combined'));
app.use(express.json());

app.use('/api/auth', authRoutes);


export default app;