import express from 'express';
import dotenv from 'dotenv';
import studentRoutes from './routes/student.routes.js';
import courseRoutes from './routes/course.routes.js';
import teacherRoutes from './routes/teacher.routes.js';
import { serveSwagger, setupSwagger } from './config/swagger.js';
import authRoutes from './routes/auth.routes.mjs';
import authenticateJWT from './middleware/auth.middleware.mjs';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use('/docs', serveSwagger, setupSwagger);

app.use('/register', authRoutes);
app.use('/login', authRoutes);

app.use('/students', authenticateJWT, studentRoutes);
app.use('/courses', authenticateJWT, courseRoutes);
app.use('/teachers', authenticateJWT, teacherRoutes);

app.get('/', (req, res) => res.send('Welcome to School API!'));

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
