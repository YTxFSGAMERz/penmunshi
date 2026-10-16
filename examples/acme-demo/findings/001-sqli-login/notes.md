SQL injection on the login form (POST /login, parameter username).
Payload ' OR '1'='1' -- - in username with any password logs in as admin.
A single quote in the same parameter returns a MySQL error page.
Tested on staging, no data was modified.
