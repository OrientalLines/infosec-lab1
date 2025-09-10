import Database from 'sqlite3';

export interface User {
    id: number;
    username: string;
    email: string;
    password_hash: string;
    created_at: string;
}

export interface Post {
    id: number;
    title: string;
    content: string;
    user_id: number;
    created_at: string;
}

class DatabaseManager {
    private db: Database.Database;

    constructor() {
        this.db = new Database.Database('app.db');
        this.initializeTables();
    }

    private initializeTables(): void {
        // Create users table with proper constraints
        this.db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

        // Create posts table for demo data
        this.db.run(`
      CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

        // Insert demo data
        this.seedDemoData();
    }

    private seedDemoData(): void {
        // Check if demo user exists
        this.db.get('SELECT id FROM users WHERE username = ?', ['demo_user'], (err, row) => {
            if (err) {
                console.error('Error checking demo user:', err);
                return;
            }

            if (!row) {
                // Hash password for demo user
                const bcrypt = require('bcrypt');
                const saltRounds = 12;
                const demoPassword = 'demo123';

                bcrypt.hash(demoPassword, saltRounds, (err: Error, hash: string) => {
                    if (err) {
                        console.error('Error hashing demo password:', err);
                        return;
                    }

                    // Insert demo user
                    this.db.run(
                        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                        ['demo_user', 'demo@example.com', hash],
                        function (err) {
                            if (err) {
                                console.error('Error inserting demo user:', err);
                                return;
                            }

                            // Insert demo posts
                            const demoPosts = [
                                { title: 'Welcome Post', content: 'This is a demo post to test the API.' },
                                { title: 'Security Best Practices', content: 'Always use parameterized queries to prevent SQL injection.' },
                                { title: 'API Development', content: 'Building secure APIs requires careful attention to authentication and authorization.' }
                            ];

                            demoPosts.forEach(post => {
                                this.db.run(
                                    'INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                                    [post.title, post.content, this.lastID],
                                    (err) => {
                                        if (err) {
                                            console.error('Error inserting demo post:', err);
                                        }
                                    }
                                );
                            });
                        }
                    );
                });
            }
        });
    }

    // User operations with parameterized queries (SQL injection protection)
    async createUser(username: string, email: string, passwordHash: string): Promise<User> {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                [username, email, passwordHash],
                function (err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({
                            id: this.lastID,
                            username,
                            email,
                            password_hash: passwordHash,
                            created_at: new Date().toISOString()
                        });
                    }
                }
            );
        });
    }

    async getUserByUsername(username: string): Promise<User | null> {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                (err, row: User) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row || null);
                    }
                }
            );
        });
    }

    async getUserById(id: number): Promise<User | null> {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE id = ?',
                [id],
                (err, row: User) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row || null);
                    }
                }
            );
        });
    }

    async getAllUsers(): Promise<User[]> {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT id, username, email, created_at FROM users',
                [],
                (err, rows: User[]) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows);
                    }
                }
            );
        });
    }

    async getPostsByUserId(userId: number): Promise<Post[]> {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC',
                [userId],
                (err, rows: Post[]) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows);
                    }
                }
            );
        });
    }

    async createPost(title: string, content: string, userId: number): Promise<Post> {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                [title, content, userId],
                function (err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({
                            id: this.lastID,
                            title,
                            content,
                            user_id: userId,
                            created_at: new Date().toISOString()
                        });
                    }
                }
            );
        });
    }

    close(): void {
        this.db.close();
    }
}

export const db = new DatabaseManager();
