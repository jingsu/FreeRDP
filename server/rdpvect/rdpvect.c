/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Vectoring server
 *
 * This service listens on a given RDP port (or FD), and accepts
 * client connections.  Over a text protocol, this service gates
 * client RDP connections to allow the client to be
 * redirected/tunnelled.
 *
 * All messages are fixed size bytes, zero padded, for size
 * simplicity.  We refer to 'server' as this service.  We refer to
 * 'watcher' as the process watching/interacting with this server over
 * the text protocol.  Note that the messages allow for embedded NULLs
 * as delimiters because some fields (e.g. tokens, passwords) allow
 * for spaces.
 *
 * SERVER: A new client, and no routing token or login information is provided
 *   <conn_id>\0new_unknown
 *
 * SERVER: A new client, and login information is provided:
 *   <conn_id>\0new_login\0<user_id>\0<domain>\0[password]
 *
 * SERVER: A redirected client, with a routing token provided:
 * Note that no user info is given when we get the routing token, since
 * it happens earlier in the connection protocol.  This is state that you
 * must track and correlate with the token.
 *   <conn_id>\0token\0<token>
 *
 *
 * Possible messages the watcher can send to manage the client(s):
 *
 * WATCHER: Close and terminate the connection.
 *   <conn_id>\0close
 *
 * WATCHER: Redirect the the client (optional: to the given IP) with the given token:
 *   <conn_id>\0issue_token\0<token>\0[redir_addr]
 *
 * WATCHER: Redirect the client to the server at the given IP:
 *   <conn_id>\0redirect\0<server_ip>
 *
 * WATCHER: Ignore the client's token and continue.
 * This is necessary because some clients pass a default Cookie as token.
 *   <conn_id>\0wipe_token
 *
 * WATCHER: Run as man-in-middle proxy to server at target IP.
 *   <conn_id>\0mimproxy\0<server_ip>
 *
 * NOTES:
 *
 * - TOKENS, wrt RDP, are ALWAYS \r\n terminated.  When the watcher
 *   interacts with the server, you must take care to always provide
 *   tokens with \r\n.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/select.h>

#include <winpr/windows.h>
#include <winpr/crt.h>
#include <winpr/synch.h>

#include <freerdp/utils/debug.h>
#include <freerdp/utils/tcp.h>
#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/crypto/crypto.h>

#define WITH_DEBUG_RDPVECT
#ifdef WITH_DEBUG_RDPVECT
#define RDPVECTLOG(fmt, ...) DEBUG_CLASS(RDPVECT, fmt, ## __VA_ARGS__)
#else
#define RDPVECTLOG(fmt, ...) DEBUG_NULL(fmt, ## __VA_ARGS__)
#endif
#define RDPVECTERR(fmt, ...) DEBUG_PRINT("ERR_RDPVECT" " %s (%s:%d)", fmt, ## __VA_ARGS__)

#define MSGSIZE 256

/* Forward Declarations */
typedef struct _rdpvect_clientargs rdpvect_clientargs_t;

/** Context info which hangs off the peer client pointer.
 */
typedef struct _rdpvect_peercontext
{
    /*
     * IMPORTANT!  The FreeRDP framework only has one context field,
     * which it internally requires.  User context is not separated
     * into a separate field.  When defining custom user context, it
     * tramples over the framework-specific context struct.  Thus, you
     * MUST include the framework context as the first field to
     * preserve the framework's assumptions.
     */
    rdpContext _p;

    /* circular ref, but access server's tag of us. */
    rdpvect_clientargs_t* clientargs;
    /* flag if this client is waiting for a command from the server. */
    BOOL waiting;

    BYTE* token;
    int tokenlen;
    char* login;
    char* domain;
    char* password;

	freerdp* target;

} rdpvect_peercontext_t;

/** Global params maintained by the server.
 */
typedef struct _rdpvect_params
{
    int localport;
    char* localpath;

    char* cert_filename;
    char* privkey_filename;

    freerdp_listener* instance;
} rdpvect_params_t;
static rdpvect_params_t g_params = {
    .localport = 0,
    .localpath = NULL,
    .cert_filename = NULL,
    .privkey_filename = NULL,
    .instance = NULL,
};

/** used by the server to track a client.
 */
typedef struct _rdpvect_clientargs
{
    rdpvect_params_t* server;
    freerdp_peer* client;

    int infd;
    int outfd;

} rdpvect_clientargs_t;

/**
 * callback
 */
static void rdpvect_peercontext_new(freerdp_peer* client, rdpvect_peercontext_t* context)
{
    RDPVECTLOG("@%s", __func__);
    context->waiting = FALSE;
}

/**
 * callback
 */
static void rdpvect_peercontext_free(freerdp_peer* client, rdpvect_peercontext_t* context)
{
    RDPVECTLOG("@%s", __func__);
    if( context->token )
        free(context->token);
}

/* NOTE:
 *
 * If you are sending a token, the default is for the client to
 * redirect to the same address it originally connected at.  If you
 * want to also send a target address with a token, the target address
 * MUST be a targetFQDN.
 *
 * If you are redirecting the client to a real computer, you CANNOT
 * send a token, and the redirect MUST be to a targetIP.
 *
 * @param tokenlen is the length not counting NULL.
 */
static BOOL
_send_redirect(freerdp_peer* client, char* token, DWORD tokenlen, const char* targetIP, const char* targetFQDN)
{
    BOOL rc = FALSE;
    BOOL freetoken = FALSE;

    /* double check the token to ensure it has a CRLF. */
    if( token != NULL )
    {
        if( tokenlen < 2 ||
            token[tokenlen-1] != '\n' ||
            token[tokenlen-2] != '\r' )
        {
            char* retoken = malloc(tokenlen+3);
            if( !retoken )
            {
                RDPVECTERR("enomem.");
                goto out;
            }
            memcpy(retoken, token, tokenlen);
            retoken[tokenlen] = '\r';
            retoken[tokenlen+1] = '\n';
            retoken[tokenlen+2] = '\0';
            tokenlen += 2;
            token = retoken;
            freetoken = TRUE;
        }
    }

    RDPVECTLOG("sending client redirect.");
    if( !freerdp_peer_redirect(client, 0,
                               targetIP,
                               (BYTE*)token, tokenlen,
                               NULL, NULL, NULL,
                               targetFQDN) )
    {
        RDPVECTERR("failed to send redirect to client.");
        goto out;
    }
    rc = TRUE;

 out:
    if( freetoken )
        free(token);
    return rc;
}

static int _mim_proxy_transitionhook(void* arg, int state)
{
/** TEMPORARY: duplicated from connection.h */
enum CONNECTION_STATE
{
	CONNECTION_STATE_INITIAL = 0,
	CONNECTION_STATE_NEGO = 1,
	CONNECTION_STATE_MCS_CONNECT = 2,
	CONNECTION_STATE_MCS_ERECT_DOMAIN = 3,
	CONNECTION_STATE_MCS_ATTACH_USER = 4,
	CONNECTION_STATE_MCS_CHANNEL_JOIN = 5,
	CONNECTION_STATE_RDP_SECURITY_COMMENCEMENT = 6,
	CONNECTION_STATE_SECURE_SETTINGS_EXCHANGE = 7,
	CONNECTION_STATE_CONNECT_TIME_AUTO_DETECT = 8,
	CONNECTION_STATE_LICENSING = 9,
	CONNECTION_STATE_MULTITRANSPORT_BOOTSTRAPPING = 10,
	CONNECTION_STATE_CAPABILITIES_EXCHANGE = 11,
	CONNECTION_STATE_FINALIZATION = 12,
	CONNECTION_STATE_ACTIVE = 13,
    CONNECTION_STATE_PIPE = 14
};
    rdpvect_peercontext_t* context = (rdpvect_peercontext_t*)arg;
    freerdp_peer* peer = context->_p.peer;
    freerdp*    target = context->target;

    // where we start piping depends on the state of the peer when
    // we're trying to set this up.
    switch( state )
    {
        case CONNECTION_STATE_NEGO:
            //case CONNECTION_STATE_ACTIVE:
    {
        freerdp_pipe(peer, target);
        return 1;
    }

    default:
        break;
    };
    return 0;
}


static void
_mim_proxy(freerdp_peer* client, const char* targetIP)
{
    rdpvect_peercontext_t* context = (rdpvect_peercontext_t*)client->context;
    freerdp* target = NULL;

    /* start a connection to the target IP. */
    target = freerdp_new();
    target->TransitionHook = _mim_proxy_transitionhook;//_mim_proxy_postnego;
    target->TransitionHookArg = context;
    context->target = target;

    freerdp_context_new(target);
    target->settings->ServerHostname = strdup(targetIP);
    target->settings->IgnoreCertificate = TRUE;
    target->settings->AuthenticationOnly = FALSE;
    target->settings->TlsSecurity = client->settings->TlsSecurity;
    target->settings->NlaSecurity = client->settings->NlaSecurity;
    target->settings->RdpSecurity = client->settings->RdpSecurity;
    target->settings->DisableEncryption = client->settings->DisableEncryption;
    target->settings->EncryptionMethods = client->settings->EncryptionMethods;
    target->settings->EncryptionLevel = client->settings->EncryptionLevel;
    //
    target->settings->DesktopWidth = client->settings->DesktopWidth;
    target->settings->DesktopHeight = client->settings->DesktopHeight;
    target->settings->ColorDepth = client->settings->ColorDepth;

    //target->settings->Authentication = FALSE;
    //  target->settings->NegotiateSecurityLayer = FALSE;

    if (!freerdp_connect(target) )
    {
        RDPVECTERR("Failed to connect to target %s", targetIP);
        return;
    }
}

/*
 * unpack a null delimited message.  This assumes the buffer is
 * MSGSIZE in size, and the output array has sufficient indices to
 * hold all the fields.
 */
static void
_unpack_message(char* buf, char** args)
{
    int argi = 0;
    int t = 0;

    //winpr_HexDump((BYTE*)buf, MSGSIZE);

    while( TRUE )
    {
        int l = strlen(&buf[t]);
        if( l == 0 )
        {
            args[argi] = NULL;
            break;
        }
        else
        {
            args[argi] = &buf[t];
        }
        t += l + 1; /* +1 to get past the NULL delim. */
        argi++;
    }
}

static int
_pack_and_send(int outfd, ...)
{
    char msg[MSGSIZE];
    va_list ap;
    int t = 0;

    memset(msg, 0, MSGSIZE);
    va_start(ap, outfd);
    while( t < MSGSIZE )
    {
        int l = 0;
        /* corner case for now, just inject 0 as clientid */
        if( t == 0 )
        {
            l = snprintf(&msg[t], MSGSIZE-t-1, "0");
        }
        /* business as usual. */
        else
        {
            char* c = va_arg(ap, char*);
            if( c == NULL ) break;
            l = snprintf(&msg[t], MSGSIZE-t-1, "%s", c);
        }

        t += l;
        msg[t] = '\0';
        t++;
    }
    if( t >= MSGSIZE )
    {
        RDPVECTERR("buffer overflow packing message packet.");
        return -1;
    }

    /* ensure double-null terminate */
    msg[t] = '\0';
    msg[MSGSIZE-1] = '\0';
    va_end(ap);
    //winpr_HexDump((BYTE*)msg, MSGSIZE);

    /* try to send. */
    ssize_t outlen = write(outfd, msg, MSGSIZE);
    if( outlen != MSGSIZE )
    {
        /* TODO: */
        RDPVECTERR("failed to write full message to server. rc=%zd", outlen);
        return -1;
    }
    return 0;
}


/** callback
 */
static BOOL
rdpvect_peer_post_connect(freerdp_peer* client)
{
    rdpvect_peercontext_t* context = (rdpvect_peercontext_t*)client->context;
    int rc;

    RDPVECTLOG("client post connect.");
    /* We will always send a message to the server and wait for an
     * action response.  The only question is which message to
     * send. */
    if( context->login != NULL || context->domain != NULL )
    {
        char* dom = context->domain;
        if( dom == NULL )
            dom = "";
        rc = _pack_and_send(context->clientargs->outfd,
                            "new_login",
                            context->login,
                            dom,
                            context->password,
                            NULL);
    }
    else
    {
        rc = _pack_and_send(context->clientargs->outfd,
                            "new_unknown", NULL);
    }

    if( rc )
    {
        return FALSE;
    }
    context->waiting = TRUE;
    return TRUE;
}

static BOOL
rdpvect_peer_activate(freerdp_peer* client)
{
    RDPVECTLOG("client activated.");
    return TRUE;
}

static void
rdpvect_peer_token(freerdp_peer* client, BYTE* token, DWORD tokenlen)
{
    /* This happens right before peer login, if a routing token is given. */
    RDPVECTLOG("client routing token: %s", (char*)token);

    if( token != NULL )
    {
        BYTE* copy = malloc(tokenlen+1);
        if( copy )
        {
            rdpvect_peercontext_t* context = (rdpvect_peercontext_t*)client->context;
            memcpy(copy, token, tokenlen);
            copy[tokenlen] = '\0'; /* ensure the copy has a null terminator.*/
            context->token = copy;
            context->tokenlen = tokenlen;

            int rc = _pack_and_send(context->clientargs->outfd,
                            "token",
                            (char*)context->token,
                            NULL);
            if( rc )
                RDPVECTERR("ERROR packing and sending message.");

            /* inform the watcher. */
            context->waiting = TRUE;
        }
        else
        {
            RDPVECTERR("ENOMEM attempting to save RDP routing token.");
        }
    }
}

static BOOL
rdpvect_peer_login(freerdp_peer* client, SEC_WINNT_AUTH_IDENTITY* identity, BOOL automatic)
{
    rdpvect_peercontext_t* context = (rdpvect_peercontext_t*)client->context;
    /* this happens right after TLS accepted.  No auth information is
     * sent during this phase if we're using TLS (which is the default
     * security mode). We only get NT secure auth info under NLS. */
    RDPVECTLOG("client peer login.");
    context->waiting = TRUE;
    return TRUE;
}

static BOOL
rdpvect_peer_capabilities(freerdp_peer* client)
{
    rdpvect_peercontext_t* context = (rdpvect_peercontext_t*)client->context;

    /* this happens after peer login.  When using TLS, the client will
     * send its login as part of the client info handshake stage.  We
     * get our first peek at that here, which the libfreerdp code
     * packages inside client->Settings->Username.  Note that some
     * clients don't pre-parse the domain portion, so if we don't get
     * a ->Domain then we should check if it's in the Username
     * portion. */
    RDPVECTLOG("client peer capabilities.");

    if( client->settings->Username )
    {
        char* username = strdup(client->settings->Username);
        if( username == NULL )
        {
            RDPVECTERR("ENOMEM attempting to extract username.");
            goto out_err;
        }
        context->login = username;
    }

    /* check for the domain field, if the client sent it. */
    if( client->settings->Domain )
    {
        char* domain = strdup(client->settings->Domain);
        if( domain == NULL )
        {
            RDPVECTERR("ENOMEM attempting to extract domain.");
            goto out_err;
        }
        context->domain = domain;
    }
    if( context->login != NULL )
    {
        /* if not, double check the username to see if the domain
         * element was embedded in a <domain>\<login> construct. */
        char* p = context->login;
        for( ; *p != '\0'; p++ )
        {
            /* look for a backslash delimiter. */
            if( *p == '\\' )
            {
                char* l = NULL;
                char* d = NULL;
                /* put a null here and strdup the two components. */
                *p = '\0';
                l = strdup(p+1);
                d = strdup(context->login);
                if( l == NULL || d == NULL )
                {
                    RDPVECTERR("ENOMEM parsing login.");
                    free(l);
                    free(d);
                    goto out_err;
                }
                free(context->login);
                context->login = l;
                /* note we always take the embedded domain element
                 * over the one explicitly given. */
                free(context->domain);
                context->domain = d;
                break;
            }
        }
    }

    /* check for the password field, if the client sent it. */
    if( client->settings->Password )
    {
        char* password = strdup(client->settings->Password);
        if( password == NULL )
        {
            RDPVECTERR("ENOMEM attempting to extract password.");
            goto out_err;
        }
        context->password = password;
    }

    RDPVECTLOG("client info: %s  ,  %s  ,  %p", context->login, context->domain, context->password);

    return TRUE;
 out_err:
    free(context->login);
    context->login = NULL;
    free(context->domain);
    context->domain = NULL;
    free(context->password);
    context->password = NULL;
    return FALSE;
}

static BOOL
_client_wait_command(freerdp_peer* client)
{
    /* wait for a message from the server and process its command. */
    rdpvect_peercontext_t* context = (rdpvect_peercontext_t*)client->context;
    int rc;
    int fd;
	fd_set rfds_set;
    FD_ZERO(&rfds_set);
    fd = context->clientargs->infd;
    FD_SET(fd, &rfds_set);

    RDPVECTLOG("WAITING FOR COMMAND....\n");

    rc = select(fd + 1, &rfds_set, NULL, NULL, NULL);
    if( rc <= 0 )
    {
        /* TODO: */
        RDPVECTERR("unexpected rc in client select waiting on server. rc=%d", rc);
        return FALSE;
    }

    /* since we only watched one FD, we can assume that FD is ready. */
    char msg[MSGSIZE];
    memset(msg, 0, MSGSIZE);
    ssize_t l = read(fd, msg, MSGSIZE);
    if( l <= 0 /*|| l != MSGSIZE*/ )
    {
        RDPVECTERR("unexpected read size %zd", l);
        return FALSE;
    }

    /* temp; add \r\n and convert spaces to nulls. */
    msg[l] = '\0';
    if( msg[l-1]=='\n' )
    {
        msg[l-1]= '\r';
        msg[l]  = '\n';
        msg[l+1]= '\0';
    }
    int i;
    for(i=0; i < l; i++)
    {
        if( msg[i]==' ')
            msg[i] = 0;
    }

    char* args[32];
    memset(args, 0, sizeof(char*)*32);

    _unpack_message(msg, args);
    /* parse up the client ID */
    if( args[0] == NULL )
    {
        /* TODO: got nothing. */
        RDPVECTERR("unexpected end of server message.");
        return FALSE;
    }
    if( strtoul(args[0], NULL, 10) != 0L )
    {
        /* TODO: */
        RDPVECTERR("server sent unexpected id: %s", args[0]);
        return FALSE;
    }

    /* parse the server command. */
    if( args[1] == NULL || strcmp(args[1], "pass") == 0 )
    {
        /* do nothing */
    }
    else if( strcmp(args[1], "close") == 0 )
    {
        RDPVECTLOG("Server commanded client close.");
        return FALSE;
    }
    else if( strcmp(args[1], "issue_token") == 0 )
    {
        /* get the token to issue */
        char* tok = args[2];
        if( tok == NULL )
        {
            RDPVECTERR("server did not issue token.");
            return FALSE;
        }
        int l = strlen(tok);
        /* get optional addr */
        char* addr = args[3];
        _send_redirect(client, tok, l, NULL, addr);
    }
    else if( strcmp(args[1], "redirect") == 0 )
    {
        /* look for target IP */
        char* targetIP = args[2];
        _send_redirect(client, NULL, 0, targetIP, NULL);
    }
    else if( strcmp(args[1], "wipe_token") == 0 )
    {
        free(context->token);
        context->token = NULL;
        context->tokenlen = 0;
    }
    else if( strcmp(args[1], "mimproxy") == 0 )
    {
        char* targetIP = args[2];
        _mim_proxy(client, targetIP);
    }
    else
    {
        RDPVECTERR("unexpected server command: %s", args[1]);
    }

    return TRUE;
}

static void*
client_thread(void* arg)
{
    int i;
	int fds;
	int max_fds;
	int rcount;
	void* rfds[32];
	fd_set rfds_set;
    freerdp_peer* client = NULL;
    rdpvect_peercontext_t* context = NULL;
    rdpvect_clientargs_t* clientargs = (rdpvect_clientargs_t*)arg;
    if( clientargs == NULL )
    {
        RDPVECTERR("ASSERT FAIL: expected client arg is NULL.");
        goto out;
    }

    client = clientargs->client;
    RDPVECTLOG("in %s , client %p", __func__, client);

    /* client context initialization. */
	client->ContextSize = sizeof(rdpvect_peercontext_t);
	client->ContextNew = (psPeerContextNew) rdpvect_peercontext_new;
	client->ContextFree = (psPeerContextFree) rdpvect_peercontext_free;
	if( !freerdp_peer_context_new(client) )
    {
        RDPVECTERR("ENOMEM: failed to init peer context.");
        goto out;
    }

    /* client object preparation */
	client->settings->CertificateFile = _strdup("server.crt");
	client->settings->PrivateKeyFile = _strdup("server.key");

	client->settings->RemoteFxCodec = FALSE;
	client->settings->ColorDepth = 32;
	client->settings->SuppressOutput = FALSE;
	client->settings->RefreshRect = FALSE;
	client->settings->NlaSecurity = FALSE;
    client->settings->TlsSecurity = TRUE;
    client->settings->RdpSecurity = FALSE;
    client->settings->ExtSecurity = FALSE;
    client->settings->DisableEncryption = TRUE;
    client->settings->Authentication = FALSE;

    /* the order in which the connect sequence comes in. */
    client->Token = rdpvect_peer_token;
    client->Logon = rdpvect_peer_login;
    client->Capabilities = rdpvect_peer_capabilities;
	client->PostConnect = rdpvect_peer_post_connect;
	client->Activate = rdpvect_peer_activate;

	client->Initialize(client);
    context = (rdpvect_peercontext_t*)client->context;
    context->clientargs = clientargs;

	while( 1 )
	{
		rcount = 0;

        /* setup descriptors to watch. */
		max_fds = 0;
		FD_ZERO(&rfds_set);

        rcount = 0;
        memset(rfds, 0, sizeof(rfds));
		if (client->GetFileDescriptor(client, rfds, &rcount) != TRUE)
		{
            RDPVECTERR("Failed to get FreeRDP file descriptor.");
			break;
		}
		for (i = 0; i < rcount; i++)
		{
			fds = (int)(long)(rfds[i]);

			if (fds > max_fds)
				max_fds = fds;

			FD_SET(fds, &rfds_set);
		}
        if( context->target )
        {
            int wcount = 0;
            void* wfds[32];
            rcount = 0;
            memset(rfds, 0, sizeof(rfds));
            memset(wfds, 0, sizeof(wfds));
            if (freerdp_get_fds(context->target, rfds, &rcount, wfds, &wcount) != TRUE)
            {
                RDPVECTERR("Failed to get FreeRDP target file descriptor.");
                break;
            }
            for( i = 0; i < rcount; i++ )
            {
                fds = (int)(long)(rfds[i]);

                if (fds > max_fds)
                    max_fds = fds;

                FD_SET(fds, &rfds_set);
            }
        }

		if (max_fds == 0)
			break;

		if (select(max_fds + 1, &rfds_set, NULL, NULL, NULL) == -1)
		{
			/* these are not really errors */
			if (!((errno == EAGAIN) ||
				(errno == EWOULDBLOCK) ||
				(errno == EINPROGRESS) ||
				(errno == EINTR))) /* signal occurred */
			{
				fprintf(stderr, "[ERROR]: select failed\n");
				break;
			}
		}

		if (client->CheckFileDescriptor(client) != TRUE)
        {
            RDPVECTERR("client check file descriptor != TRUE");
			break;
        }
        if( context->target )
        {
            if( freerdp_check_fds(context->target) != TRUE )
            {
                RDPVECTERR("target check file descriptor != TRUE");
                break;
            }
        }

        if (context->waiting)
        {
            context->waiting = FALSE;
            if(_client_wait_command(client) != TRUE)
                break;
        }
	}

    RDPVECTLOG("Client (%p) disconnected.", client);
	client->Disconnect(client);
	freerdp_peer_context_free(client);
 out:
    if( client )
        freerdp_peer_free(client);
    if( clientargs )
        free(clientargs);
    return NULL;
}

static void
callback_peer_accepted(freerdp_listener* instance, freerdp_peer* client)
{
    rdpvect_clientargs_t* clientargs = NULL;
    rdpvect_params_t* server = &g_params;

    RDPVECTLOG("accepted peer instance: %p  client: %p\n", instance, client);
    clientargs = malloc(sizeof(rdpvect_clientargs_t));
    if( !clientargs )
    {
        RDPVECTERR("enomem accepting new client.");
        goto err_out;
    }

    clientargs->server = server;
    clientargs->client = client;
    clientargs->infd = 0; /* stdin */
    clientargs->outfd = 1; /* stdout */

    /*
    pthread_t th;
    if( pthread_create(&th, 0, client_thread, clientargs) )
    {
        RDPVECTERR("err %d spawning thread to handle client connection.", errno);
        goto err_out;
    }
    pthread_detach(th);
    */
    client_thread(clientargs);

    /* success */
    return;

 err_out:
    /* If we get here, something went wrong; clean up. */
    freerdp_peer_free(client);
    free(clientargs);
}

static void
server_thread(rdpvect_params_t* server)
{
    freerdp_listener* instance = server->instance;
	int i;
	int fds;
	int max_fds;
	int rcount;
	void* rfds[32];
	fd_set rfds_set;

	memset(rfds, 0, sizeof(rfds));

	while (1)
	{
		rcount = 0;

		if (instance->GetFileDescriptor(instance, rfds, &rcount) != TRUE)
		{
            RDPVECTERR("Failed to get FreeRDP file descriptor.");
			break;
		}

		max_fds = 0;
		FD_ZERO(&rfds_set);

        /* flag freerdp's internal FDs. */
		for (i = 0; i < rcount; i++)
		{
			fds = (int)(long)(rfds[i]);

			if (fds > max_fds)
				max_fds = fds;

			FD_SET(fds, &rfds_set);
		}
		if (max_fds == 0)
			break;

		if (select(max_fds + 1, &rfds_set, NULL, NULL, NULL) == -1)
		{
			/* these are not really errors */
			if (!((errno == EAGAIN) ||
				(errno == EWOULDBLOCK) ||
				(errno == EINPROGRESS) ||
				(errno == EINTR))) /* signal occurred */
			{
                RDPVECTERR("select failed.");
				break;
			}
		}

		if (instance->CheckFileDescriptor(instance) != TRUE)
		{
            RDPVECTERR("[ERROR]: Failed to check FreeRDP file descriptor");
			break;
		}
	}
}

int main(int argc, char* argv[])
{
    int rc = 0;

    if( argc < 5)
    {
        fprintf(stderr, "usage: %s <port> <path> <tls_cert_file> <tls_key_file>\n\n", argv[0]);
        rc = 1;
        goto out;
    }

	/* Ignore SIGPIPE, otherwise an SSL_write failure could crash your server */
	signal(SIGPIPE, SIG_IGN);

    g_params.localport = atoi(argv[1]);
    g_params.localpath = strdup(argv[2]);
    g_params.cert_filename = strdup(argv[3]);
    g_params.privkey_filename = strdup(argv[4]);
    g_params.instance = freerdp_listener_new();
	g_params.instance->PeerAccepted = callback_peer_accepted;

    if( g_params.localport > 0 &&
        !g_params.instance->Open(g_params.instance, NULL, g_params.localport))
    {
        fprintf(stderr, "error opening local port %d\n", g_params.localport);
        rc = 1;
        goto out;
    }
#if 0
    if( strlen(g_params.localpath) > 0 &&
        !g_params.instance->OpenLocal(g_params.instance, g_params.localpath))
    {
        fprintf(stderr, "error opening local path %s\n", g_params.localpath);
        rc = 1;
        goto out;
    }
#endif

    server_thread(&g_params);

 out:

    if( g_params.instance != NULL )
    {
        g_params.instance->Close(g_params.instance);
        freerdp_listener_free(g_params.instance);
    }
    if( g_params.localpath != NULL )
        free(g_params.localpath);
    if( g_params.cert_filename != NULL )
        free(g_params.cert_filename);
    if( g_params.privkey_filename != NULL )
        free(g_params.privkey_filename);

    return rc;
}
