#!/bin/bash
set -e

# Create databases using environment variables
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" <<-EOSQL
    CREATE DATABASE ${POSTGRES_DB_DEMO:-demo_db};
    CREATE DATABASE ${POSTGRES_DB_TEST:-test_db};
    GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB_DEMO:-demo_db} TO $POSTGRES_USER;
    GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB_TEST:-test_db} TO $POSTGRES_USER;
EOSQL