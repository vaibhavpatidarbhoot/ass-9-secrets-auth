# Assignment 9 – Authentication & Security: Secrets 🔐

A secure web application demonstrating **user authentication**, **input validation**, **password hashing**, **JWT-based auth**, and **HttpOnly secure cookies**. Built with **Node.js**, **Express**, **EJS**, and **MongoDB Atlas**.

## 🚀 Live Demo
Deploy Link: https://ass-9-secrets-auth.onrender.com

## 📦 Tech Stack
- Node.js, Express.js
- EJS (views)
- MongoDB Atlas, Mongoose
- bcryptjs (secure hashing)
- JSON Web Tokens (JWT)
- HttpOnly cookies & express-session
- validator (email/password checks)

## ✅ Features
- **User Registration** (name, email, password)
- **Email Format Validation**
- **Password Policy**: lowercase + uppercase + number, length **6–8**
- **Show/Hide Password** toggle (UI)
- **Secure Login** with server-side validation
- **JWT Auth** stored in **HttpOnly** cookie
- **Protected Route** (`/secrets`) shows logged-in user info
- **Logout** clears cookie and redirects to login
- Responsive, modern UI

## 📁 Folder Structure

<pre>
ass-9-secrets-auth/
├── public/
│ ├── css/style.css
│ └── js/main.js
├── views/
│ ├── partials/header.ejs
│ ├── login.ejs
│ ├── register.ejs
│ └── secrets.ejs
├── index.js
├── package.json
└── README.md
</pre>
