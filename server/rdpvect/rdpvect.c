/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Vectoring server
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#include <freerdp/utils/tcp.h>
#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/crypto/crypto.h>

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

} rdpvect_peercontext_t;


typedef struct _rdpvect_params
{
    int localport;
    char* localpath;

    char* cert_filename;
    char* privkey_filename;

    freerdp_listener* instance;
} rdpvect_params_t;
static rdpvect_params_t g_params = {0};


/**
 * callback
 */
static void rdpvect_peercontext_new(freerdp_peer* client, rdpvect_peercontext_t* context)
{
    fprintf(stderr, "[DEBUG] %s\n", __func__);
}

/**
 * callback
 */
static void rdpvect_peercontext_free(freerdp_peer* client, rdpvect_peercontext_t* context)
{
    fprintf(stderr, "[DEBUG] %s\n", __func__);
}

/**
 * callback
 */
static BOOL
rdpvect_peer_post_connect(freerdp_peer* client)
{
    fprintf(stderr, "[DEBUG] client post connect.\n");
    /*
     * plain IP redirect works here.
     * Note it is not possible to redirect to a different port using the redirect PDU.
     */
    return TRUE;
}

static BOOL
rdpvect_peer_activate(freerdp_peer* client)
{
    fprintf(stderr, "[DEBUG] client activated.\n");
    return TRUE;
}

static void
rdpvect_peer_token(freerdp_peer* client, BYTE* token, DWORD tokenlen)
{
    /* This happens right before peer login, if a routing token is given. */
    fprintf(stderr, "[DEBUG] client routing token: %s\n", (char*)token);

}

static BOOL
rdpvect_peer_login(freerdp_peer* client, SEC_WINNT_AUTH_IDENTITY* identity, BOOL automatic)
{
    /* this happens right after TLS accepted.  No auth information is
     * sent during this phase if we're using TLS (which is the default
     * security mode). We only get NT secure auth info under NLS. */
    fprintf(stderr, "[DEBUG] client peer_login\n");
    return TRUE;
}

static BOOL
rdpvect_peer_capabilities(freerdp_peer* client)
{
    /* this happens after peer login.  When using TLS, the client will
     * send its login as part of the client info handshake stage.  We
     * get our first peek at that here, which the libfreerdp code
     * packages inside client->Settings->Username.  Note that some
     * clients don't pre-parse the domain portion, so if we don't get
     * a ->Domain then we should check if it's in the Username
     * portion. */
    fprintf(stderr, "[DEBUG] client peer capabilities\n");
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

	freerdp_peer* client = (freerdp_peer*) arg;
    if( client == NULL )
    {
        fprintf(stderr, "ASSERT FAIL: expected client arg is NULL.\n");
        return NULL;
    }
    fprintf(stderr, "[DEBUG] %s\n", __func__);

    /* client context initialization. */
	client->ContextSize = sizeof(rdpvect_peercontext_t);
	client->ContextNew = (psPeerContextNew) rdpvect_peercontext_new;
	client->ContextFree = (psPeerContextFree) rdpvect_peercontext_free;
	if( !freerdp_peer_context_new(client) )
    {
        fprintf(stderr, "ERROR: failed to init peer context.\n");
        return NULL;
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

    /* the order in which the connect sequence comes in. */
    client->Token = rdpvect_peer_token;
    client->Logon = rdpvect_peer_login;
    client->Capabilities = rdpvect_peer_capabilities;
	client->PostConnect = rdpvect_peer_post_connect;
	client->Activate = rdpvect_peer_activate;

	client->Initialize(client);

	memset(rfds, 0, sizeof(rfds));
	while( 1 )
	{
		rcount = 0;

		if (client->GetFileDescriptor(client, rfds, &rcount) != TRUE)
		{
			fprintf(stderr, "[ERROR]: Failed to get FreeRDP file descriptor\n");
			break;
		}

		max_fds = 0;
		FD_ZERO(&rfds_set);

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
				fprintf(stderr, "[ERROR]: select failed\n");
				break;
			}
		}

		if (client->CheckFileDescriptor(client) != TRUE)
        {
            fprintf(stderr, "[ERROR]: client check file descriptor != TRUE\n");
			break;
        }
	}

    fprintf(stderr, "[DEBUG]: Client (%p) disconnected.\n", client);
	client->Disconnect(client);
	freerdp_peer_context_free(client);
	freerdp_peer_free(client);
    return NULL;
}

static void
callback_peer_accepted(freerdp_listener* instance, freerdp_peer* client)
{
    fprintf(stderr, "[DEBUG]: %s  instance: %p  client: %p\n", __func__, instance, client);
	pthread_t th;
	pthread_create(&th, 0, client_thread, client);
	pthread_detach(th);
}

static void
server_thread(freerdp_listener* instance)
{
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
			fprintf(stderr, "[ERROR]: Failed to get FreeRDP file descriptor\n");
			break;
		}

		max_fds = 0;
		FD_ZERO(&rfds_set);

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
				fprintf(stderr, "[ERROR]: select failed\n");
				break;
			}
		}

		if (instance->CheckFileDescriptor(instance) != TRUE)
		{
			fprintf(stderr, "[ERROR]: Failed to check FreeRDP file descriptor\n");
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

    g_params.localport = atoi(argv[1]);
    g_params.localpath = strdup(argv[2]);
    g_params.cert_filename = strdup(argv[3]);
    g_params.privkey_filename = strdup(argv[4]);

	/* Ignore SIGPIPE, otherwise an SSL_write failure could crash your server */
	signal(SIGPIPE, SIG_IGN);

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

    server_thread(g_params.instance);

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
