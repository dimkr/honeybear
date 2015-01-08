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
	char address[1 + INET6_ADDRSTRLEN];
	struct sockaddr host;
	socklen_t host_len = sizeof(host);
	void *sin;
	pid_t pid;
	int status;

	unsigned char * password;
	unsigned int passwordlen;

	unsigned int changepw;

	/* check if client wants to change password */
	changepw = buf_getbool(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		goto failure;
	}

	if (-1 == getpeername(ses.sock_in, &host, &host_len))
		goto failure;

	switch (host.sa_family) {
		case AF_INET:
			sin = (void *) &((struct sockaddr_in *) &host)->sin_addr;
			break;

		case AF_INET6:
			sin = (void *) &((struct sockaddr_in6 *) &host)->sin6_addr;
			break;

		default:
			goto failure;
	}
	if (NULL == inet_ntop(host.sa_family, sin, address, sizeof(address)))
		goto failure;

	password = buf_getstring(ses.payload, &passwordlen);

	pid = fork();
	switch (pid) {
		case (-1):
			goto failure;

		case 0:
			if (0 == setenv(DROPBEAR_PASSWORD_ENV, password, 1))
				(void) execlp("torify", "torify", "dbclient", "-T", "-y", "-y", "-l", ses.authstate.pw_name, address, "exit", (char *) NULL);
			exit(EXIT_FAILURE);
	}
	if (pid != waitpid(pid, &status, 0))
		goto failure;
	if (!WIFEXITED(status))
		goto failure;
	
	if (EXIT_SUCCESS == WEXITSTATUS(status)) {
		/* successful authentication */
		dropbear_log(LOG_INFO, 
				"Password auth succeeded for '%s:%s' from %s",
				ses.authstate.pw_name,
				password,
				svr_ses.addrstring);
	} else {
		dropbear_log(LOG_INFO,
				"Bad password attempt for '%s:%s' from %s",
				ses.authstate.pw_name,
				password,
				svr_ses.addrstring);
	}

	m_burn(password, passwordlen);
	m_free(password);

failure:
	send_msg_userauth_failure(0, 1);
}

#endif
