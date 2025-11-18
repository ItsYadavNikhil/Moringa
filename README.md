# Pure Moringa E-Commerce Platform

Welcome to the official repository for the Pure Moringa e-commerce website. This is a full-stack web application built to sell premium organic moringa powder directly to customers.

The site provides a complete shopping experience, from browsing the product to secure payment and user account management. It also includes a comprehensive dashboard for administrators to manage orders, view sales analytics, and update product statuses.

About Our Product

Moringa powder, often called the "miracle tree," is a nutrient-dense superfood packed with vitamins, minerals, and antioxidants. This website is dedicated to selling high-quality, premium organic moringa powder, sourced and processed to retain its powerful health benefits.

# Features

--> <strong>Customer Experience:</strong>

Clean, responsive, single-page design.

Simple and secure checkout process.

Secure customer registration and login.

Customer dashboard to view order history.

PDF receipt generation for all orders.

--> <strong>Admin Dashboard:</strong>

Secure admin-only login with Multi-Factor Authentication (MFA).

A comprehensive dashboard with sales analytics, revenue charts, and order statistics.

Detailed order management: view, update status (e.g., "processing", "shipped"), and manage customer details.

Export order data to CSV.

--> <strong>Security:</strong>

Separate authentication systems for customers and admins.

Password hashing using werkzeug.security.

MFA support for both admins and customers using pyotp.

CSRF protection on all forms and API endpoints.

Secure session management with HTTP-only and secure cookies.


--> <strong>Technical Stack</strong>

This project is built with a modern, secure Python backend and a dynamic frontend.
    
Backend: Python with the Flask micro-framework.
    
Database: MySQL (for production) with Flask-SQLAlchemy as the ORM.
    
Payments: Integrated with Razorpay for a seamless payment gateway.

Authentication: Flask-Login for session management, Flask-WTF for forms, and pyotp for MFA.
    
PDF Generation: ReportLab is used to create and serve PDF invoices.
    
Environment: python-dotenv manages all environment variables.
    
Production Server: Deployed on Railway using the Gunicorn WSGI server.

# Local Installation and Setup Guide

Follow these steps to run the project on your local machine for development.

```bash

1. Clone the Repository
```

First, clone this repository to your local machine:

```bash
git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
cd your-repository-name
```

2. Create and Activate a Virtual Environment

It's a best practice to use a virtual environment to manage dependencies.

On macOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows:

```bash
python -m venv venv
.\venv\Scripts\activate
```

3. Install Dependencies

Install all the required Python packages from the requirements.txt file.

```bash
pip install -r requirements.txt
```

(This includes Flask, Flask-SQLAlchemy, gunicorn, razorpay, pyotp, reportlab, and all other necessary libraries.)

4. Set Up Environment Variables

Create a file named .env in the root of your project. This file stores your secret keys and local configuration.

Copy the contents of .env.example (if it exists) or use the template below:

.env file template:

```env
# Generate a new secret key for your app
# You can use: python -c "import secrets; print(secrets.token_hex(16))"
SECRET_KEY='your_super_secret_key_here'

# Your local database URL. We recommend installing MySQL locally.
# Example for MySQL: mysql+pymysql://root:your_password@localhost/moringa_db
# For simple testing, you can use SQLite:
DATABASE_URL='sqlite:///moringa_orders.db'

# Razorpay API Keys (from your Razorpay dashboard)
RAZORPAY_KEY_ID='your_razorpay_key_id'
RAZORPAY_KEY_SECRET='your_razorpay_key_secret'

# Flask environment variables for development
FLASK_APP=app.py
FLASK_DEBUG=1
FLASK_RUN_PORT=5001

# Optional: SMTP Email settings for sending receipts
SMTP_SERVER='smtp.gmail.com'
SMTP_PORT=587
SMTP_USER='your-email@gmail.com'
SMTP_PASS='your-gmail-app-password'
```


5. Initialize the Database

Run the custom init-db Flask command we created. This will create all the necessary tables in your database (e.g., orders, customer, admin).

```bash
flask init-db
```

You should see a message like "Default admin user created: admin/admin123".

6. Run the Application

You can now start the local development server using the flask run command.
```bash
flask run
```

Your application will be running and accessible at:
http://127.0.0.1:5001/

The admin panel is available at:
http://127.0.0.1:5001/admin/login
(Default credentials: admin / admin123)
