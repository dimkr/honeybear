This is Dropbear 0.64, hacked so:
  - password authentication fails, always
  - the plain-text user name and password get written to syslog
  - dbclient is executed after each authentication attempt, to try the user name/password combo against the client

dk
