# Secure Web API Implementation

A comprehensive secure web API built with Node.js, Express, and Bun, implementing industry-standard security practices including JWT authentication, SQL injection protection, XSS prevention, and automated security scanning.

## 🚀 Features

### Core Functionality
- **JWT Authentication**: Secure token-based authentication with 24-hour expiration
- **Password Hashing**: bcrypt with salt rounds for secure password storage
- **SQLite Database**: Built-in database with parameterized queries
- **RESTful API**: Clean, well-documented endpoints
- **Input Validation**: Comprehensive validation for all user inputs

### Security Measures Implemented

#### 🔐 Authentication & Authorization
- JWT token issuance upon successful login
- Protected routes with middleware authentication
- Password hashing with bcrypt (12 salt rounds)
- Secure credential validation

#### 🛡️ SQL Injection Protection
- Parameterized queries using SQLite prepared statements
- Input sanitization and validation
- No string concatenation for SQL queries

#### 🧹 XSS Protection
- HTML entity encoding for all user-generated content
- Data sanitization before sending responses
- Content Security Policy headers

#### 📊 Rate Limiting
- General API rate limiting (100 requests/15min)
- Stricter auth endpoint limiting (5 attempts/15min)
- Automatic blocking of excessive requests

#### 🔒 Security Headers
- Helmet.js for comprehensive security headers
- CORS protection with configurable origins
- Content Security Policy
- X-Frame-Options, X-Content-Type-Options, etc.

### API Endpoints

#### Public Endpoints
- `GET /health` - Health check endpoint
- `POST /auth/login` - User authentication
- `POST /api/users` - User registration

#### Protected Endpoints (Require JWT Token)
- `GET /api/data` - Get user data and posts
- `POST /api/posts` - Create new post

### Demo User
- **Username**: `demo_user`
- **Password**: `demo123`

## 🛠️ Technology Stack

- **Runtime**: Bun (v1.2.20)
- **Framework**: Express.js v5
- **Database**: SQLite3 with Bun
- **Authentication**: JWT (jsonwebtoken)
- **Password Hashing**: bcrypt
- **Security**: Helmet, CORS, express-rate-limit
- **Language**: TypeScript

## 📦 Installation & Setup

```bash
# Install dependencies
bun install

# Start the server
bun run start

# Or run in development mode with auto-reload
bun run dev
```

The server will start on `http://localhost:3000`

## 🧪 Testing

### Automated Testing
```bash
# Run comprehensive security tests
bun run test:api
```

### Manual Testing with curl

```bash
# Health check
curl http://localhost:3000/health

# Login (get JWT token)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo_user","password":"demo123"}'

# Access protected data (replace TOKEN with actual JWT)
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:3000/api/data

# Create new user
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","email":"new@example.com","password":"securepass123"}'
```

## 🔍 Security Testing Results

### ✅ All Security Tests Passed

1. **Authentication**: JWT tokens properly validated
2. **SQL Injection**: Parameterized queries prevent injection attacks
3. **XSS Protection**: User input properly sanitized
4. **Rate Limiting**: Excessive requests automatically blocked
5. **Password Security**: bcrypt hashing prevents plain text storage
6. **Input Validation**: All inputs validated before processing

### SAST/SCA Integration

The project includes comprehensive CI/CD pipeline with:

- **Static Application Security Testing (SAST)**:
  - npm audit for dependency vulnerabilities
  - JSHint for code quality analysis
  - GitHub CodeQL for advanced static analysis

- **Software Composition Analysis (SCA)**:
  - OWASP Dependency-Check via retire.js
  - Automated vulnerability scanning
  - Critical vulnerability blocking

## 📁 Project Structure

```
├── index.ts           # Main API server
├── database.ts        # SQLite database manager
├── test-api.ts        # Security testing script
├── package.json       # Dependencies and scripts
├── tsconfig.json      # TypeScript configuration
├── .github/
│   └── workflows/
│       └── ci.yml     # GitHub Actions CI/CD pipeline
└── README.md          # This documentation
```

## 🚦 CI/CD Pipeline

### Automated Security Scanning
- Runs on every push and pull request
- SAST analysis with npm audit and CodeQL
- SCA with retire.js for dependency vulnerabilities
- Critical vulnerability detection and blocking
- Security report artifacts generation

### Pipeline Features
- Node.js 18 environment
- Automated dependency installation
- Multi-stage security analysis
- Report generation and artifact storage
- Build verification
- API startup testing

## 🔐 Security Implementation Details

### JWT Authentication Flow
1. User sends login credentials
2. Server validates credentials against hashed passwords
3. JWT token generated with user data and 24h expiration
4. Token returned to client for subsequent requests
5. Protected routes validate JWT before processing

### SQL Injection Prevention
- All database queries use parameterized statements
- User inputs never concatenated into SQL strings
- Input validation before database operations
- SQLite prepared statements for all queries

### XSS Protection Strategy
- HTML entity encoding for all user content
- Recursive sanitization of nested objects
- CSP headers to prevent script injection
- Input validation at API boundaries

### Rate Limiting Configuration
- General API: 100 requests per 15 minutes
- Authentication: 5 attempts per 15 minutes
- Automatic IP-based blocking
- Configurable limits per endpoint

## 📊 Database Schema

```sql
-- Users table
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Posts table
CREATE TABLE posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## 🏃‍♂️ Quick Start

1. **Clone and install**:
   ```bash
   git clone <repository-url>
   cd lab1
   bun install
   ```

2. **Start the server**:
   ```bash
   bun run start
   ```

3. **Test authentication**:
   ```bash
   curl -X POST http://localhost:3000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"demo_user","password":"demo123"}'
   ```

4. **Run security tests**:
   ```bash
   bun run test:api
   ```

## 📋 Assignment Requirements Compliance

✅ **Stack Selection**: Node.js + Express with Bun runtime
✅ **Project Initialization**: npm/bun package management
✅ **Git Integration**: Repository initialized and configured
✅ **API Endpoints**: 3+ endpoints implemented with security
✅ **Database**: SQLite with secure query patterns
✅ **SQLi Protection**: Parameterized queries throughout
✅ **XSS Protection**: Data sanitization implemented
✅ **Authentication**: JWT with secure password hashing
✅ **CI/CD Pipeline**: GitHub Actions with SAST/SCA
✅ **Security Testing**: Comprehensive test suite
✅ **Documentation**: Complete API documentation

## 🔗 Links

- [Bun Runtime](https://bun.sh)
- [Express.js](https://expressjs.com)
- [SQLite](https://sqlite.org)
- [JWT](https://jwt.io)
- [OWASP Security Guidelines](https://owasp.org)

---

**Note**: This implementation follows OWASP security guidelines and industry best practices for secure API development.
