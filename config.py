import os

class Config:
    # A secret key is needed for session management and other security features.
    # It should be a long, random string. NEVER share this in a public repository.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess-this-secret-key-for-sure'
    # The path to our remote PostgreSQL database from Neon
    SQLALCHEMY_DATABASE_URI = 'postgresql://neondb_owner:npg_imWUL8wvxlH0@ep-icy-pine-ae606u7v-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
