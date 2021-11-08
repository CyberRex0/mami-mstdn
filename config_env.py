import os
DB_HOST=os.environ.get('DB_HOST')
DB_USER=os.environ.get('DB_USER')
DB_PASS=os.environ.get('DB_PASS')
DB_NAME=os.environ.get('DB_NAME')

if not DB_HOST:
    from config import *
DEBUG=os.environ.get('PORT') is None
PORT=os.environ.get('PORT')