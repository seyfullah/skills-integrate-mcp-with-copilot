# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities and participants
- Teacher-only signup and unregister actions
- Hashed teacher passwords and expiring login sessions

## Getting Started

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. From the repository root, create a teacher account. The command securely prompts for a username and password and writes only a password hash to `src/teachers.json`:

   ```
   python -m src.manage_teachers
   ```

   `src/teachers.json` is local configuration and is intentionally ignored by Git. The checked-in `src/teachers.example.json` shows its format.

3. From the repository root, run the application:

   ```
   uvicorn src.app:app --reload
   ```

4. Open your browser and go to:
   - Activities: http://localhost:8000/
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                            |
| ------ | ----------------------------------------------------------------- | ---------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities and participants                                    |
| GET    | `/auth/status`                                                    | Check whether the current browser is logged in as a teacher             |
| POST   | `/auth/login`                                                     | Log in with a teacher username and password                             |
| POST   | `/auth/logout`                                                    | Log out and expire the teacher session                                  |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Add a participant (teacher login required)                              |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Remove a participant (teacher login required)                       |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

Activity data and login sessions are stored in memory, which means activity changes and sessions reset when the server restarts. Teacher credentials are stored locally in `src/teachers.json` as PBKDF2-SHA256 password hashes. Use HTTPS when deploying so the session cookie is secure.
