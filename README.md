# Gosok Angka Backend API

Backend API untuk aplikasi Gosok Angka - Game gosok kartu berhadiah.

## 🚀 Quick Start

### Prerequisites
- Node.js 14+ 
- MongoDB Atlas Account
- Git

### Installation

1. Clone repository
```bash
git clone https://github.com/YOUR_USERNAME/gosokangka-backend.git
cd gosokangka-backend
```

2. Install dependencies
```bash
npm install
```

3. Setup environment variables
Buat file `.env` di root folder:
```env
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
PORT=5000
```

4. Run development server
```bash
npm run dev
```

## 📋 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/admin/login` - Admin login

### User Routes
- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update profile
- `GET /api/user/history` - Scratch history
- `GET /api/user/winners` - User's prizes

### Game Routes  
- `POST /api/game/scratch` - Scratch card (1x per day)

### Admin Routes
- `GET /api/admin/dashboard` - Dashboard stats
- `GET /api/admin/users` - List all users
- `POST /api/admin/users/:userId/reset-password` - Reset user password
- `GET /api/admin/game-settings` - Get game settings
- `PUT /api/admin/game-settings` - Update game settings
- `GET /api/admin/prizes` - List all prizes
- `POST /api/admin/prizes` - Add new prize
- `PUT /api/admin/prizes/:prizeId` - Update prize
- `DELETE /api/admin/prizes/:prizeId` - Delete prize

### Chat Routes
- `GET /api/user/chat/history` - Get user chat history
- `POST /api/user/chat/send` - Send message (user)
- `GET /api/admin/chat/users` - Get chat users (admin)
- `POST /api/admin/chat/send` - Send message (admin)

## 🔐 Default Admin Account

```
Username: admin
Password: GosokAngka2024!
```

⚠️ **IMPORTANT**: Change this password after first login!

## 🚀 Deployment to Railway

1. Push code to GitHub
2. Login to [Railway](https://railway.app)
3. Create new project from GitHub repo
4. Add environment variables in Railway dashboard
5. Deploy!

## 📦 Project Structure

```
gosokangka-backend/
├── server.js          # Main server file
├── package.json       # Dependencies
├── .gitignore        # Git ignore file
├── railway.json      # Railway config
├── README.md         # Documentation
└── .env             # Environment variables (don't commit!)
```

## 🛠️ Technologies Used

- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MongoDB** - Database
- **Mongoose** - ODM
- **JWT** - Authentication
- **Bcrypt** - Password hashing
- **CORS** - Cross-origin support

## 📱 Frontend Integration

Update API URL in frontend:
```javascript
// Development
const API_BASE_URL = 'http://localhost:5000/api';

// Production (after Railway deployment)
const API_BASE_URL = 'https://your-app.up.railway.app/api';
```

## 🔧 Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| MONGODB_URI | MongoDB connection string | mongodb+srv://... |
| JWT_SECRET | Secret key for JWT | random_secret_key |
| PORT | Server port | 5000 |

## 📈 Database Schema

- **Users** - App users
- **Admins** - Admin accounts  
- **Prizes** - Available prizes
- **Scratches** - Scratch records
- **Winners** - Winner records
- **GameSettings** - Game configuration
- **Chats** - Chat messages

## 🐛 Troubleshooting

### MongoDB Connection Error
- Check connection string in `.env`
- Whitelist IP in MongoDB Atlas

### Port Already in Use
- Change PORT in `.env`
- Kill process using the port

### Module Not Found
- Run `npm install` again
- Delete `node_modules` and reinstall

## 📞 Support

Jika ada masalah atau pertanyaan:
- Create GitHub issue
- Contact developer

## 📄 License

ISC License

---

Made with ❤️ for Gosok Angka
