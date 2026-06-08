FROM postgres:16-alpine

# Copy init scripts — Postgres runs these in filename order on first start
COPY init/01_schema.sql /docker-entrypoint-initdb.d/01_schema.sql
COPY init/02_audit.sql /docker-entrypoint-initdb.d/02_audit.sql
COPY init/03_seed.sql /docker-entrypoint-initdb.d/03_seed.sql
COPY init/04_update_passwords.sh /docker-entrypoint-initdb.d/04_update_passwords.sh
RUN chmod +x /docker-entrypoint-initdb.d/04_update_passwords.sh

# Postgres config tuning for a security-focused workload
RUN echo "log_connections = on" >> /usr/local/share/postgresql/postgresql.conf.sample && \
    echo "log_disconnections = on" >> /usr/local/share/postgresql/postgresql.conf.sample && \
    echo "log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '" >> /usr/local/share/postgresql/postgresql.conf.sample && \
    echo "log_statement = 'ddl'" >> /usr/local/share/postgresql/postgresql.conf.sample

EXPOSE 5432