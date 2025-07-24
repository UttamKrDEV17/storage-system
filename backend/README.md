.
├── src/
│   ├── app.js                     # Main application entry point (Express app setup)
│   ├── server.js                  # Starts the server and connects to DB
│
│   ├── config/
│   │   ├── index.js               # Central configuration (env vars, constants)
│   │   ├── db.js                  # Database connection (Mongoose)
│   │   └── minio.js               # MinIO client initialization and configuration
│   │
│   ├── middlewares/
│   │   ├── auth.middleware.js     # Middleware for authentication (JWT, Session validation)
│   │   ├── error.middleware.js    # Global error handling middleware
│   │   ├── upload.middleware.js   # Handles Busboy parsing for file uploads
│   │   └── permission.middleware.js # For checking file/folder access permissions
│   │
│   ├── models/
│   │   ├── File.js                # Your File schema (as provided)
│   │   ├── Folder.js              # Your Folder schema (as provided)
│   │   ├── Session.js             # Your Session schema (as provided)
│   │   └── User.js                # Placeholder: You'll need a User schema
│   │
│   ├── controllers/
│   │   ├── auth.controller.js     # User registration, login, logout, session management
│   │   ├── file.controller.js     # CRUD for files (upload, download, delete, update metadata)
│   │   ├── folder.controller.js   # CRUD for folders (create, rename, delete, move)
│   │   ├── user.controller.js     # User profile management
│   │   └── shared.controller.js   # Logic for sharing files/folders, managing access
│   │   └── trash.controller.js    # Logic for managing trashed items (restore, permanent delete)
│   │
│   ├── routes/
│   │   ├── index.js               # Aggregates all routes
│   │   ├── auth.routes.js         # Routes for authentication
│   │   ├── file.routes.js         # Routes for file operations
│   │   ├── folder.routes.js       # Routes for folder operations
│   │   ├── user.routes.js         # Routes for user profiles
│   │   ├── shared.routes.js       # Routes for sharing functionality
│   │   └── trash.routes.js        # Routes for trash bin operations
│   │
│   ├── services/                  # Encapsulates business logic and interacts with models/MinIO
│   │   ├── file.service.js        # Business logic for files (e.g., upload to MinIO, save to DB)
│   │   ├── folder.service.js      # Business logic for folders (e.g., nested operations, renaming)
│   │   ├── auth.service.js        # Business logic for auth (e.g., token generation, session handling)
│   │   ├── minio.service.js       # Direct MinIO interactions (upload stream, download stream, delete)
│   │   └── user.service.js        # Business logic for user-related operations
│   │
│   ├── utils/
│   │   ├── ApiError.js            # Custom error class for API responses
│   │   ├── ApiResponse.js         # Standardized success response format
│   │   ├── asyncHandler.js        # Wrapper for async route handlers to catch errors
│   │   └── constants.js           # Application-wide constants (e.g., MinIO bucket names)
│   │
│   └── validators/                # Input validation (e.g., using Joi or Express-validator)
│       ├── auth.validators.js
│       ├── file.validators.js
│       └── folder.validators.js
│
├── .env                           # Environment variables (e.g., DB URI, MinIO credentials, JWT secret)
├── .gitignore
├── package.json
├── package-lock.json
└── README.md