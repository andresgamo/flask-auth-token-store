# Flask RESTful API with MongoDB

This project is a Flask-based RESTful API designed to handle user registration, login, and file uploads. It uses MongoDB as the backend database and includes features like JWT-based authentication, password hashing, and data validation using Marshmallow.

## Features

- **User Registration and Login:** Users can register with a username and password, and log in to obtain a JWT token for authenticated access.
- **File Uploads:** Authenticated users can upload files, which are securely stored in MongoDB.
- **JWT Authentication:** Secure access to protected routes using JSON Web Tokens (JWT).
- **Data Validation:** Input data is validated using Marshmallow schemas to ensure completeness and correctness.
- **Modular Design:** The application is structured into separate modules for better maintainability and scalability.

## Setup and Installation

### Prerequisites

- Docker and Docker Compose installed on your machine.

### Getting Started

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/andresgamo/flask-auth-token-store.git
   cd flask-auth-token-store
   ```
2. **Environment Variables:**

The application requires the following environment variables:

- **SECRET_KEY:** A secret key for JWT token generation.
- **MONGO_URI:** MongoDB connection string.

3. ## Run the Application

Use Docker Compose to build and run the application:

  ```bash
  docker-compose up --build
  ```

This will start both the Flask application and MongoDB in Docker containers.

## Access the API

The API will be accessible at [http://localhost:8000](http://localhost:8000).

## API Endpoints

- **POST `/register`:** Register a new user.
- **POST `/login`:** Log in an existing user to receive a JWT token.
- **POST `/upload`:** Upload a file (authentication required).

## Example Requests

### User Registration:

  ```bash
  curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword"}'
  ```

### User Login:

  ```bash
  curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword"}'
  ```

### File Upload:
  ```bash
    curl -X POST http://localhost:8000/upload \
    -H "Authorization: Bearer <JWT_TOKEN>" \
    -F "file=@/path/to/your/file" \
    -F "username=testuser"
  ```

## Project Structure

- **`app.py`:** Main application entry point.
- **`auth_middleware.py`:** Middleware for JWT authentication.
- **`data_validation.py`:** Data validation and helper functions.
- **`db_manager.py`:** Database operations and interactions with MongoDB.
- **`dependency_resolver.py`:** Manages dependencies across the application.
- **`schemas.py`:** Marshmallow schemas for data validation.
- **`utility.py`:** Utility functions like document serialization.
- **`docker-compose.yml`:** Docker Compose configuration.
- **`Dockerfile`:** Dockerfile for building the Flask application image.
- **`requirements.txt`:** Python dependencies.








