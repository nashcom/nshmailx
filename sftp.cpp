#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <libssh2.h>
#include <libssh2_sftp.h>

#include "lib.hpp" 


int tcp_connect (const char *pszHost, uint16_t nPort)
{
    struct addrinfo hints = {0};
    struct addrinfo *pRes = NULL;
    struct sockaddr_in sin = {0};
    struct timeval tv = {0};
    fd_set wfds = {0};
    int nSock = -1;
    int flags;
    int rc;
    int nErr = 0;
    socklen_t nErrLen = sizeof (nErr);
    char szIP[INET_ADDRSTRLEN] = {0};

    if (IsNullStr (pszHost))
        return -1;

    if (0 == nPort)
        nPort = 22;

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo (pszHost, NULL, &hints, &pRes);
    if ((0 != rc) || (NULL == pRes))
        return -1;

    memcpy (&sin, pRes->ai_addr, sizeof (sin));
    sin.sin_port = htons (nPort);

    freeaddrinfo (pRes);

    inet_ntop (AF_INET,
               &sin.sin_addr,
               szIP,
               sizeof (szIP));
    printf ("Connecting to %s (%s:%u)\n",
            pszHost,
            szIP,
            (unsigned)nPort);

    nSock = socket (AF_INET, SOCK_STREAM, 0);
    if (nSock < 0)
        return -1;

    /* Set non-blocking */
    flags = fcntl (nSock, F_GETFL, 0);
    fcntl (nSock, F_SETFL, flags | O_NONBLOCK);

    rc = connect (nSock,
                  (struct sockaddr *)&sin,
                  sizeof (sin));
    if ((0 != rc) && (EINPROGRESS != errno))
    {
        close (nSock);
        return -1;
    }

    FD_ZERO (&wfds);
    FD_SET (nSock, &wfds);

    tv.tv_sec  = 10;
    tv.tv_usec = 0;

    rc = select (nSock + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0)
    {
        close (nSock);
        return -1;
    }

    getsockopt (nSock,
                SOL_SOCKET,
                SO_ERROR,
                &nErr,
                &nErrLen);

    if (0 != nErr)
    {
        close (nSock);
        errno = nErr;
        return -1;
    }

    /* Restore blocking mode */
    fcntl (nSock, F_SETFL, flags);

    return nSock;
}


void LogErrorSSH2 (LIBSSH2_SESSION *pSession, const char *pszErrorText)
{
    char *pErrMsg = NULL;
    int errlen = 0;

    if (NULL == pSession)
    {
        fprintf(stderr, "%s - SSH error: NO SESSION\n", pszErrorText ? pszErrorText : "SSH error");
        return;
    }

    libssh2_session_last_error (pSession, &pErrMsg, &errlen, 0);

    if (IsNullStr (pszErrorText))
        fprintf (stderr, "SSH error: %s\n", pErrMsg ? pErrMsg : "UNKNOWN");
    else
        fprintf (stderr, "%s - SSH error: %s\n", pszErrorText, pErrMsg ? pErrMsg : "UNKNOWN");
}


#define SHA256_LEN 32

bool xxcheck_ssh_hostkey (LIBSSH2_SESSION *pSession)
{
    const unsigned char *pszHash;
    char szHash[(SHA256_LEN * 2) + 1];
    int i;

    if (!pSession)
        return false;

    pszHash = (const unsigned char *)
        libssh2_hostkey_hash(
            pSession,
            LIBSSH2_HOSTKEY_HASH_SHA256
        );

    if (!pszHash)
        return false;

    for (i = 0; i < SHA256_LEN; i++)
        snprintf(szHash + (i * 2), 3, "%02x", pszHash[i]);

    szHash[SHA256_LEN * 2] = '\0';

    printf("SSH host key SHA-256: %s\n", szHash);
    return true;
}


static const char * ssh_hostkey_type_name (int nType)
{
    switch (nType)
    {
        case LIBSSH2_HOSTKEY_TYPE_RSA:
            return "ssh-rsa";

        case LIBSSH2_HOSTKEY_TYPE_DSS:
            return "ssh-dss";

        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
            return "ecdsa-sha2-nistp256";

        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
            return "ecdsa-sha2-nistp384";

        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
            return "ecdsa-sha2-nistp521";

        case LIBSSH2_HOSTKEY_TYPE_ED25519:
            return "ssh-ed25519";

        default:
            return "unknown";
    }
}


bool check_ssh_hostkey (LIBSSH2_SESSION *pSession, const char * pszExpectedHostKey)
{
    const unsigned char *pKey = NULL;
    size_t nKeyLen = 0;
    int nKeyType   = 0;
    int nB64Len    = 0;
    int i = 0;

    unsigned char szHash[SHA256_DIGEST_LENGTH] = {0};
    unsigned char szB64[EVP_ENCODE_LENGTH(SHA256_DIGEST_LENGTH)] = {0};

    if (!pSession)
        return false;

    pKey = (const unsigned char *) libssh2_session_hostkey (pSession, &nKeyLen, &nKeyType);

    if (NULL == pKey || (0 == nKeyLen))
        return false;

    /* SHA256 over raw SSH host key blob (OpenSSH-compatible) */
    SHA256 (pKey, nKeyLen, szHash);

    /* Base64 encode */
    nB64Len = EVP_EncodeBlock (szB64, szHash, SHA256_DIGEST_LENGTH);

    if (nB64Len <= 0)
        return false;

    /* Strip '=' padding (OpenSSH style) */
    for (i = nB64Len - 1; i >= 0 && szB64[i] == '='; i--)
        szB64[i] = '\0';

    printf ("SSH host key [%s] SHA256:%s\n", ssh_hostkey_type_name (nKeyType), szB64);

    if (IsNullStr (pszExpectedHostKey))
      return true;

    if (0 == strcmp (pszExpectedHostKey, (const char *) szB64))
        return true;

    return false;
}


int sftp_put (const char *pszHost,
              uint16_t   nPort,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
	      const char *pszExpectedHostKey)
{
    int fdLocal = -1;
    int nSock   = -1;
    int rc      =  1; /* Assume error until completed */

    LIBSSH2_SESSION *pSession    = NULL;
    LIBSSH2_SFTP *pSftp          = NULL;
    LIBSSH2_SFTP_HANDLE *pHandle = NULL;

    char szBuf[16384] = {0};

    if (IsNullStr (pszHost))
    {
        LogError ("Missing host parameter");
        return -1;
    }

    if (IsNullStr (pszUser))
    {
        LogError ("Missing user parameter");
        return -1;
    }

    if (IsNullStr (pszPass))
    {
        LogError ("Missing password parameter");
        return -1;
    }

    if (IsNullStr (pszLocalFile))
    {
        LogError ("Missing local file parameter");
        return -1;
    }

    if (IsNullStr (pszRemotePath))
    {
        LogError ("Missing remote path parameter");
        return -1;
    }

    if (0 == nPort)
        nPort = 22;

    /* First check if the file exists */
    fdLocal = open (pszLocalFile, O_RDONLY);
    if  (fdLocal < 0)
    {
        LogError ("Unable to open local file");
        goto Done;
    }

    /* init/term should be process wide, but this routine is only called once */
    if  (0 != libssh2_init (0))
    {
        LogError ("libssh2_init failed");
        goto Done;
    }

    nSock = tcp_connect (pszHost, nPort);
    if  (nSock < 0)
    {
        LogError ("TCP connect failed");
        goto Done;
    }

    pSession = libssh2_session_init ();
    if  (!pSession)
    {
        LogError ("Session init failed");
        goto Done;
    }

    libssh2_session_method_pref (
        pSession,
        LIBSSH2_METHOD_HOSTKEY,
        "ssh-ed25519,"
        "ecdsa-sha2-nistp256,"
        "rsa-sha2-512,"
        "rsa-sha2-256");

    if (0 != libssh2_session_handshake (pSession, nSock))
    {
        LogErrorSSH2 (pSession, "SSH handshake failed");
        goto Done;
    }

    check_ssh_hostkey (pSession, pszExpectedHostKey);

    if (0 != libssh2_userauth_password (pSession, pszUser, pszPass))
    {
        LogErrorSSH2 (pSession, "Authentication failed");
        goto Done;
    }

    pSftp = libssh2_sftp_init (pSession);
    if  (!pSftp)
    {
        LogErrorSSH2 (pSession, "SFTP init failed");
        goto Done;
    }

    pHandle = libssh2_sftp_open (
        pSftp,
        pszRemotePath,
        LIBSSH2_FXF_WRITE |
        LIBSSH2_FXF_CREAT |
        LIBSSH2_FXF_TRUNC,
        0644);

    if  (NULL == pHandle)
    {
        LogError ("Unable to open remote file");
        goto Done;
    }

    while (true)
    {
        ssize_t cbRead    = 0;
        ssize_t cbLeft    = 0;
        ssize_t cbWritten = 0;
        char *p = NULL;

        cbRead = read (fdLocal, szBuf, sizeof (szBuf));

        if (cbRead == 0)
            break; /* EOF */

        if (cbRead < 0)
        {
            LogError ("Local file read error");
            goto Done;
        }

        p = szBuf;
        cbLeft = cbRead;

        while (cbLeft > 0)
        {
            cbWritten = libssh2_sftp_write (pHandle, p, cbLeft);
            if (cbWritten < 0)
            {
                LogError ("SFTP write error");
                goto Done;
            }

            p += cbWritten;
            cbLeft -= cbWritten;
        }
    }

    printf ("Upload successful: %s\n", pszRemotePath);
    rc = 0;

Done:

    if  (-1 != fdLocal)
    {
        close (fdLocal);
        fdLocal = -1;
    }

    if  (pHandle)
    {
        libssh2_sftp_close (pHandle);
    }

    if  (pSftp)
    {
        libssh2_sftp_shutdown (pSftp);
    }

    if  (pSession)
    {
        libssh2_session_disconnect (pSession, "done");
        libssh2_session_free (pSession);
    }

    if  (nSock >= 0)
    {
        close (nSock);
    }

    libssh2_exit ();
    return rc;
}


