# AuthBackend
JWT based authentication backend system

# Running project in docker

Running the Django Project with Docker
This guide will walk you through the steps to run the Django project using Docker.

Prerequisites
Before you begin, ensure you have the following installed on your machine:

Docker Engine: [Install Docker](https://www.docker.com/)

## 1. Clone a repository:
    git clone https://github.com/acharyapuru/AuthBackend.git

## 2. Navigate to the project directory:
    cd AuthBackend
    
## 3. Change to the src directory
    cd src

## 4. Create and configure the .env file:

Create .env file in the src/ directory to configure environment variables. Populate it with the environment variables given in env.sample file. For example:
- SECRET_KEY=project's secrtet key here
- DEBUG=True
- ALLOWED_HOSTS=*
- DB_ENGINE='django.db.backends.postgresql'
- POSTGRES_DB='AuthBackend'
- POSTGRES_USER='postgres'
- POSTGRES_PASSWORD='postgres'
- DB_HOST=db
- DB_PORT=5432
- CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
- CSRF_TRUSTED_ORIGINS=http://localhost:3000,http://localhost:3001
- STATIC_URL=/static/
- STATIC_ROOT=staticfiles
- STATICFILES_DIRS=static
- MEDIA_URL=/media/
- MEDIA_ROOT=media
- EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend'
- EMAIL_USE_TLS=True
- EMAIL_HOST='smtp.gmail.com'
- EMAIL_HOST_USER=youe-email-id
- EMAIL_HOST_PASSWORD=
- EMAIL_PORT=587
- ACCESS_TOKEN_LIFETIME=15
- REFRESH_TOKEN_LIFETIME=30
- OTP_LIFETIME=1440
- MAX_OTP_RESENT_ATTEMPT=5
- OTP_RESENT_BLOCK_TIME=1440 # in minutes
- OTP_CONT_RESENT_BLOCK_TIME=1 # in minutes
- MAX_OTP_RETRY=5
- OTP_RETRY_BLOCK_TIME=5


## 5. Build and run the Docker containers:
    docker-compose build
    docker-compose up 
    
## 6. Apply database migrations:
    docker-compose exec web python manage.py migrate

## 7. Create a superuser (optional):
If you need to create a superuser for accessing the Django admin:

    docker-compose exec web python manage.py createsuperuser


## 8. Access the application:
Once the Docker containers are running, you can access the application by navigating to http://localhost:8000 in your web browser.


-----------------------------------------------------------------------------------------------------------------------------------
## Setting Up Email Functionality
    
    To enable email functionality in your application, you'll need to set up an email account and obtain the necessary credentials.
    
    #### Step 1: Create an Email Account
    
    You can use any email provider, but here are instructions for popular options:
    
    #### Gmail
    
    1. Go to [Google Account](https://myaccount.google.com/).
    2. Create a new account or use an existing one.
    3. **Enable 2-Step Verification**:
       - Go to the "Security" section of your Google Account.
       - Under "Signing in to Google," select "2-Step Verification" and follow the prompts to set it up.
    4. **Generate an App Password**:
       - Go back to the "Security" section.
       - Under "Signing in to Google," select "App passwords."
       - Choose "Mail" as the app and "Other" for the device, then name it (e.g., "MyApp").
       - Click "Generate" to get your app password. Use this password in your `.env` file.

## Acknowledgments
- [Django](https://www.djangoproject.com/)
- [Django REST Framework](https://www.django-rest-framework.org/)
- [Poetry](https://python-poetry.org/)
- [PostgreSQL](https://www.postgresql.org/)
- [Docker](https://www.docker.com/)
