/* source: xio-proxy.c */
/* Copyright Gerhard Rieger and contributors (see file CHANGES) */
/* Published under the GNU General Public License V.2, see file COPYING */

/* this file contains the source for opening addresses of HTTP proxy CONNECT
   type */

#include "xiosysincludes.h"

#if WITH_PROXY

#include "xioopen.h"
#include "xio-socket.h"
#include "xio-ip.h"
#include "xio-ipapp.h"
#include "xio-ascii.h"	/* for base64 encoding of authentication */

#include "xio-proxy.h"


#define PROXYPORT "8080"

static int xioopen_proxy_connect(int argc, const char *argv[], struct opt *opts, int xioflags, xiofile_t *fd, const struct addrdesc *addrdesc);

const struct optdesc opt_proxyport = { "proxyport", NULL, OPT_PROXYPORT, GROUP_HTTP, PH_LATE, TYPE_STRING, OFUNC_SPEC };
const struct optdesc opt_ignorecr  = { "ignorecr",  NULL, OPT_IGNORECR,  GROUP_HTTP, PH_LATE, TYPE_BOOL,  OFUNC_SPEC };
const struct optdesc opt_http_version              = { "http-version",              NULL,            OPT_HTTP_VERSION,              GROUP_HTTP, PH_LATE, TYPE_STRING,  OFUNC_SPEC };
const struct optdesc opt_proxy_resolve   = { "proxy-resolve",   "resolve", OPT_PROXY_RESOLVE,   GROUP_HTTP, PH_LATE, TYPE_BOOL,  OFUNC_SPEC };
const struct optdesc opt_proxy_authorization  = { "proxy-authorization",  "proxyauth", OPT_PROXY_AUTHORIZATION,  GROUP_HTTP, PH_LATE, TYPE_STRING,  OFUNC_SPEC };
const struct optdesc opt_proxy_authorization_file  = { "proxy-authorization-file",  "proxyauthfile", OPT_PROXY_AUTHORIZATION_FILE,  GROUP_HTTP, PH_LATE, TYPE_STRING,  OFUNC_SPEC };

const struct addrdesc xioaddr_proxy_connect = { "PROXY", 3, xioopen_proxy_connect, GROUP_FD|GROUP_SOCKET|GROUP_SOCK_IP4|GROUP_SOCK_IP6|GROUP_IP_TCP|GROUP_HTTP|GROUP_CHILD|GROUP_RETRY, 0, 0, 0 HELP(":<proxy-server>:<host>:<port>") };


/*0#define CONNLEN 40*/	/* "CONNECT 123.156.189.123:65432 HTTP/1.0\r\n\0" */
#define CONNLEN 281	/* "CONNECT <255bytes>:65432 HTTP/1.0\r\n\0" */

/* states during receiving answer */
enum {
   XIOSTATE_HTTP1,	/* 0 or more bytes of first line received, no \r */
   XIOSTATE_HTTP2,	/* first line received including \r */
   XIOSTATE_HTTP3,	/* received status and \r\n */
   XIOSTATE_HTTP4,	/* within header */
   XIOSTATE_HTTP5,	/* within header, \r */
   XIOSTATE_HTTP6,	/* received status and 1 or more headers, \r\n */
   XIOSTATE_HTTP7,	/* received status line, ev. headers, \r\n\r */
   XIOSTATE_HTTP8,	/* complete answer received */
   XIOSTATE_ERROR	/* error during HTTP headers */
} ;


/* get buflen bytes from proxy server;
   handles EINTR;
   returns <0 when error occurs
*/
static ssize_t
   xioproxy_recvbytes(struct single *sfd, char *buff, size_t buflen, int level) {
   ssize_t result;
   do {
      /* we need at least buflen bytes... */
      result = Read(sfd->fd, buff, buflen);
   } while (result < 0 && errno == EINTR);	/*! EAGAIN? */
   if (result < 0) {
      Msg4(level, "read(%d, %p, "F_Zu"): %s",
	   sfd->fd, buff, buflen, strerror(errno));
      return result;
   }
   if (result == 0) {
      Msg(level, "proxy_connect: connection closed by proxy");
   }
   return result;
}


#define BUFLEN 2048


static int xioopen_proxy_connect(
	int argc,
	const char *argv[],
	struct opt *opts,
	int xioflags,
	xiofile_t *xxfd,
	const struct addrdesc *addrdesc)
{
      /* we expect the form: host:host:port */
   struct single *sfd = &xxfd->stream;
   struct opt *opts0 = NULL;
   struct proxyvars struct_proxyvars = { 0 }, *proxyvars = &struct_proxyvars;
   /* variables to be filled with address option values */
   bool dofork = false;
   /* */
   int pf = PF_UNSPEC;
   union sockaddr_union us_sa,   *us = &us_sa;
   socklen_t uslen = sizeof(us_sa);
   struct addrinfo **themarr, *themp;
   int i;
   const char *proxyname; char *proxyport = NULL;
   const char *targetname, *targetport;
   int ipproto = IPPROTO_TCP;
   bool needbind = false;
   bool lowport = false;
   int socktype = SOCK_STREAM;
   int level;
   int result;

   if (argc != 4) {
      xio_syntax(argv[0], 3, argc-1, addrdesc->syntax);
      return STAT_NORETRY;
   }
   proxyname = argv[1];
   targetname = argv[2];
   targetport = argv[3];

   if (sfd->howtoend == END_UNSPEC)
      sfd->howtoend = END_SHUTDOWN;
   if (applyopts_single(sfd, opts, PH_INIT) < 0)
      return -1;
   applyopts(sfd, 1, opts, PH_INIT);

   retropt_int(opts, OPT_SO_TYPE, &socktype);

   retropt_bool(opts, OPT_FORK, &dofork);

   if (retropt_string(opts, OPT_PROXYPORT, &proxyport) < 0) {
      if ((proxyport = strdup(PROXYPORT)) == NULL) {
	 errno = ENOMEM;  return -1;
      }
   }

   result = _xioopen_proxy_prepare(proxyvars, opts, targetname, targetport,
				   sfd->para.socket.ip.ai_flags);
   if (result != STAT_OK)
      return result;

   Notice4("opening connection to %s:%u via proxy %s:%s",
      proxyvars->targetaddr, proxyvars->targetport, proxyname, proxyport);

   i = 0;
   do {      /* loop over retries (failed connect and proxy-request attempts) */

    level = E_INFO;

    result =
      _xioopen_ipapp_prepare(opts, &opts0, proxyname, proxyport,
			     &pf, ipproto,
			     sfd->para.socket.ip.ai_flags,
			     &themarr, us, &uslen,
			     &needbind, &lowport, socktype);
   if (result != STAT_OK)
       return result;

      /* Loop over themlist */
      i = 0;
      themp = themarr[i++];
      while (themp != NULL) {
	 Notice4("opening connection to %s:%u via proxy %s:%s",
		 proxyvars->targetaddr, proxyvars->targetport, proxyname, proxyport);
#if WITH_RETRY
	 if (sfd->forever || sfd->retry || themarr[i] != NULL) {
	    level = E_INFO;
	 } else
#endif /* WITH_RETRY */
	    level = E_ERROR;

   result =
      _xioopen_connect(sfd,
		       needbind?us:NULL, uslen,
		       themp->ai_addr, themp->ai_addrlen,
		       opts, pf?pf:themp->ai_family, socktype, IPPROTO_TCP, lowport, level);
       if (result == STAT_OK)
	  break;
       themp = themarr[i++];
       if (themp == NULL) {
	  result = STAT_RETRYLATER;
      }
      switch (result) {
      case STAT_OK: break;
#if WITH_RETRY
      case STAT_RETRYLATER:
      case STAT_RETRYNOW:
	 if (sfd->forever || sfd->retry) {
	    --sfd->retry;
	    if (result == STAT_RETRYLATER)
	       Nanosleep(&sfd->intervall, NULL);
	    continue;
	 }
#endif /* WITH_RETRY */
      default:
	 xiofreeaddrinfo(themarr);
	 return result;
      }
      }
      xiofreeaddrinfo(themarr);
      applyopts(sfd, -1, opts, PH_ALL);

      if ((result = _xio_openlate(sfd, opts)) < 0)
	 return result;

      result = _xioopen_proxy_connect(sfd, proxyvars, level);
      switch (result) {
      case STAT_OK: break;
#if WITH_RETRY
      case STAT_RETRYLATER:
      case STAT_RETRYNOW:
	 if (sfd->forever || sfd->retry--) {
	    if (result == STAT_RETRYLATER)  Nanosleep(&sfd->intervall, NULL);
	    continue;
	 }
#endif /* WITH_RETRY */
      default:
	 return result;
      }

      if (dofork) {
	 xiosetchilddied();	/* set SIGCHLD handler */
      }

#if WITH_RETRY
      if (dofork) {
	 pid_t pid;
	 int level = E_ERROR;
	 if (sfd->forever || sfd->retry) {
	    level = E_WARN;
	 }
	 while ((pid = xio_fork(false, level, sfd->shutup)) < 0) {
	    if (sfd->forever || --sfd->retry) {
	       Nanosleep(&sfd->intervall, NULL); continue;
	    }
	    return STAT_RETRYLATER;
	 }

	 if (pid == 0) {	/* child process */
	    sfd->forever = false;  sfd->retry = 0;
	    break;
	 }

	 /* parent process */
	 Close(sfd->fd);
	 Nanosleep(&sfd->intervall, NULL);
	 dropopts(opts, PH_ALL);
	 opts = copyopts(opts0, GROUP_ALL);
	 continue;
      } else
#endif /* WITH_RETRY */
      {
	 break;
      }

   } while (true);	/* end of complete open loop - drop out on success */

   Notice4("successfully connected to %s:%u via proxy %s:%s",
	   proxyvars->targetaddr, proxyvars->targetport,
	   proxyname, proxyport);

   return 0;
}


int _xioopen_proxy_prepare(
	struct proxyvars *proxyvars,
	struct opt *opts,
	const char *targetname,
	const char *targetport,
	const int ai_flags[2]) {
   union sockaddr_union host;
   socklen_t socklen = sizeof(host);
   int rc;

   retropt_bool(opts, OPT_IGNORECR, &proxyvars->ignorecr);
   retropt_bool(opts, OPT_PROXY_RESOLVE, &proxyvars->doresolve);
   retropt_string(opts, OPT_HTTP_VERSION,             &proxyvars->version);
   retropt_string(opts, OPT_PROXY_AUTHORIZATION, &proxyvars->authstring);
   retropt_string(opts, OPT_PROXY_AUTHORIZATION_FILE, &proxyvars->authfile);

   if (proxyvars->authfile) {
      int authfd;
      off_t length;
      ssize_t bytes;

      /* if we have a file containing authentication credentials and they were also
	 provided on the command line, something is misspecified */
      if (proxyvars->authstring) {
	 Error("Only one of options proxy-authorization and proxy-authorization-file allowed");
	 return STAT_NORETRY;
      }
      authfd = Open(proxyvars->authfile, O_RDONLY, 0);
      if (authfd < 0) {
	 Error2("open(\"%s\", O_RDONLY): %s", proxyvars->authfile, strerror(errno));
	 return STAT_NORETRY;
      }
      /* go to the end of our proxy auth file to
	 figure out how long our proxy auth is */
      if ((length = Lseek(authfd, 0, SEEK_END)) < 0) {
	 Error2("lseek(<%s>, 0, SEEK_END): %s",
		proxyvars->authfile, strerror(errno));
	 return STAT_RETRYLATER;
      }
      proxyvars->authstring = Malloc(length+1);
      /* go back to the beginning */
      Lseek(authfd, 0, SEEK_SET);
      /* read our proxy info from the file */
      if ((bytes = Read(authfd, proxyvars->authstring, (size_t) length)) < 0) {
	 Error3("read(<%s>, , "F_Zu"): %s", proxyvars->authfile, length, strerror(errno));
	 free(proxyvars->authstring);
	 Close(authfd);
	 return STAT_NORETRY;
      }
      if (bytes < length) {
	 Error3("read(<%s>, , "F_Zu"): got only "F_Zu" bytes",
		proxyvars->authfile, length, bytes);
	 Close(authfd);
	 return STAT_NORETRY;
      }
      proxyvars->authstring[bytes] = '\0';	/* string termination */
      Close(authfd);
   }

   if (proxyvars->doresolve) {
      /* currently we only resolve to IPv4 addresses. This is in accordance to
	 RFC 2396; however once it becomes clear how IPv6 addresses should be
	 represented in CONNECT commands this code might need to be extended */
      rc = xioresolve(targetname, targetport, PF_INET/*!?*/,
		      SOCK_STREAM, IPPROTO_TCP,
		      &host, &socklen, ai_flags);
      if (rc != STAT_OK) {
	 proxyvars->targetaddr = strdup(targetname);
      } else {
#define LEN 16	/* www.xxx.yyy.zzz\0 */
	 if ((proxyvars->targetaddr = Malloc(LEN)) == NULL) {
	    return STAT_RETRYLATER;
	 }
	 snprintf(proxyvars->targetaddr, LEN, "%u.%u.%u.%u",
		  ((unsigned char *)&host.ip4.sin_addr.s_addr)[0],
		  ((unsigned char *)&host.ip4.sin_addr.s_addr)[1],
		  ((unsigned char *)&host.ip4.sin_addr.s_addr)[2],
		  ((unsigned char *)&host.ip4.sin_addr.s_addr)[3]);
#undef LEN
      }
   } else {
      proxyvars->targetaddr = strdup(targetname);
   }

   proxyvars->targetport = htons(parseport(targetport, IPPROTO_TCP));

   return STAT_OK;
}

int _xioopen_proxy_connect(struct single *sfd,
			   struct proxyvars *proxyvars,
			   int level) {
   size_t offset;
   char request[CONNLEN];	/* HTTP connection request line */
   int rv;
   char buff[BUFLEN+1];		/* for receiving HTTP reply headers */
#if CONNLEN > BUFLEN
#error not enough buffer space
#endif
   char textbuff[2*BUFLEN+1];	/* just for sanitizing print data */
   char *eol = buff;
   int state;
   ssize_t sresult;

   /* generate proxy request header - points to final target */
   if (proxyvars->version == NULL) {
      proxyvars->version = "1.0";
   }
   rv = snprintf(request, CONNLEN, "CONNECT %s:%u HTTP/%s\r\n",
		 proxyvars->targetaddr, proxyvars->targetport, proxyvars->version);
   if (rv >= CONNLEN || rv < 0) {
      Error("_xioopen_proxy_connect(): PROXY CONNECT buffer too small");
      return -1;
   }

   /* send proxy CONNECT request (target addr+port) */
   * xiosanitize(request, strlen(request), textbuff) = '\0';
   Info1("sending \"%s\"", textbuff);
   /* write errors are assumed to always be hard errors, no retry */
   if (writefull(sfd->fd, request, strlen(request)) < 0) {
      Msg4(level, "write(%d, %p, "F_Zu"): %s",
	   sfd->fd, request, strlen(request), strerror(errno));
      if (Close(sfd->fd) < 0) {
	 Info2("close(%d): %s", sfd->fd, strerror(errno));
      }
      return STAT_RETRYLATER;
   }

   if (proxyvars->authstring) {
      /* send proxy authentication header */
#     define XIOAUTHHEAD "Proxy-authorization: Basic "
#     define XIOAUTHLEN  27
      static const char *authhead = XIOAUTHHEAD;
#     define HEADLEN 256
      char *header, *next;

      /* ...\r\n\0 */
      if ((header =
	   Malloc(XIOAUTHLEN+((strlen(proxyvars->authstring)+2)/3)*4+3))
	  == NULL) {
	 return -1;
      }
      strcpy(header, authhead);
      next = xiob64encodeline(proxyvars->authstring,
			      strlen(proxyvars->authstring),
			      strchr(header, '\0'));
      *next = '\0';
      Info1("sending \"%s\\r\\n\"", header);
      *next++ = '\r';  *next++ = '\n'; *next++ = '\0';
      if (writefull(sfd->fd, header, strlen(header)) < 0) {
	 Msg4(level, "write(%d, %p, "F_Zu"): %s",
	      sfd->fd, header, strlen(header), strerror(errno));
	 if (Close(sfd->fd) < 0) {
	    Info2("close(%d): %s", sfd->fd, strerror(errno));
	 }
	 return STAT_RETRYLATER;
      }

      free(header);
   }

   Info("sending \"\\r\\n\"");
   if (writefull(sfd->fd, "\r\n", 2) < 0) {
      Msg2(level, "write(%d, \"\\r\\n\", 2): %s",
	   sfd->fd, strerror(errno));
      if (Close(sfd->fd) < 0) {
	 Info2("close(%d): %s", sfd->fd, strerror(errno));
      }
      return STAT_RETRYLATER;
   }

   /* request is kept for later error messages */
   *strstr(request, " HTTP") = '\0';

   /* receive proxy answer; looks like "HTTP/1.0 200 .*\r\nHeaders..\r\n\r\n" */
   /* socat version 1 depends on a valid fd for data transfer; address
      therefore cannot buffer data. So, to prevent reading beyond the end of
      the answer headers, only single bytes are read. puh. */
   state = XIOSTATE_HTTP1;
   offset = 0;	/* up to where the buffer is filled (relative) */
   /*eol;*/	/* points to the first lineterm of the current line */
   do {
      sresult = xioproxy_recvbytes(sfd, buff+offset, 1, level);
      if (sresult <= 0) {
	 state = XIOSTATE_ERROR;
	 break;	/* leave read cycles */
      }

      switch (state) {

      case XIOSTATE_HTTP1:
	 /* 0 or more bytes of first line received, no '\r' yet */
	 if (*(buff+offset) == '\r') {
	    eol = buff+offset;
	    state = XIOSTATE_HTTP2;
	    break;
	 }
	 if (proxyvars->ignorecr && *(buff+offset) == '\n') {
	    eol = buff+offset;
	    state = XIOSTATE_HTTP3;
	    break;
	 }
	 break;

      case XIOSTATE_HTTP2:
	 /* first line received including '\r' */
	 if (*(buff+offset) != '\n') {
	    state = XIOSTATE_HTTP1;
	    break;
	 }
	 state = XIOSTATE_HTTP3;
	 break;

      case XIOSTATE_HTTP3:
	 /* received status (first line) and "\r\n" */
	 if (*(buff+offset) == '\r') {
	    state = XIOSTATE_HTTP7;
	    break;
	 }
	 if (proxyvars->ignorecr && *(buff+offset) == '\n') {
	    state = XIOSTATE_HTTP8;
	    break;
	 }
	 state = XIOSTATE_HTTP4;
	 break;

      case XIOSTATE_HTTP4:
	 /* within header */
	 if (*(buff+offset) == '\r') {
	    eol = buff+offset;
	    state = XIOSTATE_HTTP5;
	    break;
	 }
	 if (proxyvars->ignorecr && *(buff+offset) == '\n') {
	    eol = buff+offset;
	    state = XIOSTATE_HTTP6;
	    break;
	 }
	 break;

      case XIOSTATE_HTTP5:
	 /* within header, '\r' received */
	 if (*(buff+offset) != '\n') {
	    state = XIOSTATE_HTTP4;
	    break;
	 }
	 state = XIOSTATE_HTTP6;
	 break;

      case XIOSTATE_HTTP6:
	 /* received status (first line) and 1 or more headers, "\r\n" */
	 if (*(buff+offset) == '\r') {
	    state = XIOSTATE_HTTP7;
	    break;
	 }
	 if (proxyvars->ignorecr && *(buff+offset) == '\n') {
	    state = XIOSTATE_HTTP8;
	    break;
	 }
	 state = XIOSTATE_HTTP4;
	 break;

      case XIOSTATE_HTTP7:
	 /* received status (first line), 0 or more headers, "\r\n\r" */
	 if (*(buff+offset) == '\n') {
	    state = XIOSTATE_HTTP8;
	    break;
	 }
	 if (*(buff+offset) == '\r') {
	    if (proxyvars->ignorecr) {
	       break;	/* ignore it, keep waiting for '\n' */
	    } else {
	       state = XIOSTATE_HTTP5;
	    }
	    break;
	 }
	 state = XIOSTATE_HTTP4;
	 break;

      }
      ++offset;

      /* end of status line reached */
      if (state == XIOSTATE_HTTP3) {
	 char *ptr;
	 /* set a terminating null - on or after CRLF? */
	 *(buff+offset) = '\0';

	 * xiosanitize(buff, Min(offset, (sizeof(textbuff)-1)>>1), textbuff)
	    = '\0';
	 Info1("proxy_connect: received answer \"%s\"", textbuff);
	 *eol = '\0';
	 * xiosanitize(buff, Min(strlen(buff), (sizeof(textbuff)-1)>>1),
		       textbuff) = '\0';
	 if (strncmp(buff, "HTTP/1.0 ", 9) &&
	     strncmp(buff, "HTTP/1.1 ", 9)) {
	    /* invalid answer */
	    Msg1(level, "proxy: invalid answer \"%s\"", textbuff);
	    return STAT_RETRYLATER;
	 }
	 ptr = buff+9;

	 /* skip multiple spaces */
	 while (*ptr == ' ')  ++ptr;

	 /* HTTP answer */
	 if (strncmp(ptr, "200", 3)) {
	    /* not ok */
	    /* CERN:
	       "HTTP/1.0 200 Connection established"
	       "HTTP/1.0 400 Invalid request "CONNECT 10.244.9.3:8080 HTTP/1.0" (unknown method)"
	       "HTTP/1.0 403 Forbidden - by rule"
	       "HTTP/1.0 407 Proxy Authentication Required"
	       Proxy-Authenticate: Basic realm="Squid proxy-caching web server"
>  50 72 6f 78 79 2d 61 75 74 68 6f 72 69 7a 61 74  Proxy-authorizat
>  69 6f 6e 3a 20 42 61 73 69 63 20 61 57 4e 6f 63  ion: Basic aWNoc
>  32 56 73 59 6e 4e 30 4f 6e 4e 30 63 6d 56 75 5a  2VsYnN0OnN0cmVuZ
>  32 64 6c 61 47 56 70 62 51 3d 3d 0d 0a           2dlaGVpbQ==..
                b64encode("username:password")
	       "HTTP/1.0 500 Can't connect to host"
	    */
	    /* Squid:
	       "HTTP/1.0 400 Bad Request"
	       "HTTP/1.0 403 Forbidden"
	       "HTTP/1.0 503 Service Unavailable"
	       interesting header: "X-Squid-Error: ERR_CONNECT_FAIL 111" */
	    /* Apache:
	       "HTTP/1.0 400 Bad Request"
	       "HTTP/1.1 405 Method Not Allowed"
	    */
	    /* WTE:
	       "HTTP/1.1 200 Connection established"
	       "HTTP/1.1 404 Host not found or not responding, errno:  79"
	       "HTTP/1.1 404 Host not found or not responding, errno:  32"
	       "HTTP/1.1 404 Host not found or not responding, errno:  13"
	    */
	    /* IIS:
	       "HTTP/1.1 404 Object Not Found"
	    */
	    ptr += 3;
	    while (*ptr == ' ')  ++ptr;

	    Msg2(level, "%s: %s", request, ptr);
	    return STAT_RETRYLATER;
	 }

	 /* ok!! */
	 /* "HTTP/1.0 200 Connection established" */
	 /*Info1("proxy: \"%s\"", textbuff+13);*/
	 offset = 0;

      } else if (state == XIOSTATE_HTTP6) {
      /* end of a header line reached */
	 char *endp;

	 /* set a terminating null */
	 *(buff+offset) = '\0';

	 endp =
	    xiosanitize(buff, Min(offset, (sizeof(textbuff)-1)>>1),
			textbuff);
	 *endp = '\0';
	 Info1("proxy_connect: received header \"%s\"", textbuff);
	 offset = 0;
      }

   } while (state != XIOSTATE_HTTP8 && offset < BUFLEN);

   if (state == XIOSTATE_ERROR) {
      return STAT_RETRYLATER;
   }

   if (offset >= BUFLEN) {
      Msg1(level, "proxy answer exceeds %d bytes, aborting", BUFLEN);
      return STAT_NORETRY;
   }

   return STAT_OK;
}

#endif /* WITH_PROXY */

