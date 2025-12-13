#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <libssh2.h>
#include <libssh2_sftp.h>

#include "lib.hpp"
#include "sftp.hpp"


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


int sftp_transfer (int        Mode,
                   const char *pszHost,
                   uint16_t   nPort,
                   uint16_t   nHash,
                   const char *pszUser,
                   const char *pszPass,
                   const char *pszLocalFile,
                   const char *pszRemotePath,
                   const char *pszExpectedHostKey)
{
    int fdLocal = -1;
    int nSock   = -1;
    int rc      =  1; /* Assume error */

    size_t  nBufferSize = 1024*1024;
    ssize_t cbIO      = 0;
    ssize_t cbWritten = 0;
    ssize_t cbTotal   = 0;
    long diff_ms = 0;

    LIBSSH2_SESSION *pSession    = NULL;
    LIBSSH2_SFTP *pSftp          = NULL;
    LIBSSH2_SFTP_HANDLE *pHandle = NULL;

    char szEmpty[] = "";
    char szSHA[(EVP_MAX_MD_SIZE * 2) + 1] = {0};
    char szNumStr[1024] = {0};
    char szPerformanceString[1024] = {0};
    char *pBuffer = NULL;
    char *p = NULL;

    const char *pszHashName = szEmpty;
    unsigned char szDigest[EVP_MAX_MD_SIZE+1] = {0};
    unsigned int  nDigestLen = 0;

    EVP_MD_CTX *pMdCtx = NULL;
    const EVP_MD *pMd  = NULL;

    struct timespec start = {0};
    struct timespec end   = {0};

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

   if ( (Mode != SFTP_MODE_GET) && (Mode != SFTP_MODE_PUT) )
    {
        LogError ("Invalid mode specified");
        return -1;
    }

    if (0 == nPort)
        nPort = 22;

    pBuffer = (char *) malloc (nBufferSize);

    clock_gettime (CLOCK_MONOTONIC, &start);

    /* Open local file */
    if (SFTP_MODE_PUT == Mode)
        fdLocal = open (pszLocalFile, O_RDONLY);
    else if (SFTP_MODE_GET == Mode)
        fdLocal = open (pszLocalFile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    else
    {
        LogError ("Invalid mode");
        goto Done;
    }

    if (fdLocal < 0)
    {
        LogError ("Unable to open local file");
        goto Done;
    }

    if (0 != libssh2_init (0))
    {
        LogError ("libssh2_init failed");
        goto Done;
    }

    nSock = tcp_connect (pszHost, nPort);
    if (nSock < 0)
    {
        LogError ("TCP connect failed");
        goto Done;
    }

    pSession = libssh2_session_init ();
    if (!pSession)
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
        "rsa-sha2-256"
    );

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
    if (NULL == pSftp)
    {
        LogErrorSSH2 (pSession, "SFTP init failed");
        goto Done;
    }

    /* Open remote file */
    if (SFTP_MODE_PUT == Mode)
    {
        pHandle = libssh2_sftp_open (
            pSftp,
            pszRemotePath,
            LIBSSH2_FXF_WRITE |
            LIBSSH2_FXF_CREAT |
            LIBSSH2_FXF_TRUNC,
            0644);
    }
    else if (SFTP_MODE_GET == Mode)
    {
        pHandle = libssh2_sftp_open (
            pSftp,
            pszRemotePath,
            LIBSSH2_FXF_READ,
            0);
    }

    if (NULL == pHandle)
    {
        LogError ("Unable to open remote file");
        goto Done;
    }

    switch (nHash)
    {
        case 1:
            pMd = EVP_sha1();
            break;

        case 256:
            pMd = EVP_sha256();
            break;

        case 384:
            pMd = EVP_sha384();
            break;

        case 512:
            pMd = EVP_sha512();
            break;
    }

    if (pMd)
    {
        pszHashName = EVP_MD_get0_name (pMd);

        if (NULL == pszHashName)
            pszHashName = szEmpty;

        pMdCtx = EVP_MD_CTX_new();
        if (!pMdCtx)
        {
            LogError ("Cannot init hash context");
            goto Done;
        }

        if (1 != EVP_DigestInit_ex (pMdCtx, pMd, NULL))
        {
            LogError ("Cannot init digest");
            goto Done;
        }
    }
    else if (nHash)
    {
        LogError ("Invalid hash algorithm");
        goto Done;
    }

    /* Transfer loop */
    while (true)
    {
        if (SFTP_MODE_PUT == Mode)
        {
            cbIO = read (fdLocal, pBuffer, nBufferSize);
            if (cbIO == 0)
                break;

            if (cbIO < 0)
            {
                LogError ("Local file read error");
                goto Done;
            }

            if (pMdCtx)
            {
                if (1 != EVP_DigestUpdate (pMdCtx, pBuffer, cbIO))
                {
                    LogError ("Digest update failed");
                    goto Done;
                }
            }

            cbTotal += cbIO;
            p = pBuffer;

            while (cbIO > 0)
            {
                cbWritten = libssh2_sftp_write (pHandle, p, cbIO);

                if (cbWritten < 0)
                {
                    LogError ("SFTP write error");
                    goto Done;
                }

                p    += cbWritten;
                cbIO -= cbWritten;
            }
        }
        else if (SFTP_MODE_GET == Mode)
        {
            cbIO = libssh2_sftp_read (pHandle, pBuffer, nBufferSize);

            if (cbIO == 0)
                break;

            if (cbIO < 0)
            {
                LogError ("SFTP read error");
                goto Done;
            }

            if (pMdCtx)
            {
                if (1 != EVP_DigestUpdate (pMdCtx, pBuffer, cbIO))
                {
                    LogError ("Digest update failed");
                    goto Done;
                }
            }

            cbTotal += cbIO;
            p = pBuffer;

            while (cbIO > 0)
            {
                cbWritten = write (fdLocal, p, cbIO);
                if (cbWritten <= 0)
                {
                    LogError ("Local file write error");
                    goto Done;
                }

                p    += cbWritten;
                cbIO -= cbWritten;
            }
        }
        else
        {
            goto Done;
        }
    }

    clock_gettime (CLOCK_MONOTONIC, &end);
    diff_ms = time_diff_ms (start, end);

    if (pMdCtx)
    {
        if (1 != EVP_DigestFinal_ex (pMdCtx, szDigest, &nDigestLen))
        {
            LogError ("Digest final failed");
            goto Done;
        }

        for (unsigned int i = 0; i < nDigestLen; i++)
            snprintf (szSHA + (i * 2), 3, "%02x", szDigest[i]);
    }

    GetBytesHumanReadable (cbTotal, sizeof (szNumStr), szNumStr);
    CalculatePerformanceString (diff_ms, cbTotal, sizeof(szPerformanceString), szPerformanceString);
    printf ("Mail send in %1.1f sec (Size: %s, Speed: %s)\n", (double)diff_ms / 1000.0, szNumStr, szPerformanceString);

    if (*szSHA)
    {
        if (SFTP_MODE_PUT == Mode)
            printf ("Upload successful: %s -> %s (size %s, transfer: %s, %s: %s)\n", pszLocalFile, pszRemotePath, szNumStr, szPerformanceString, pszHashName, szSHA);
        else if (SFTP_MODE_GET == Mode)
            printf ("Download successful: %s -> %s (size: %s, transfer: %s, %s: %s)\n", pszRemotePath, pszLocalFile, szNumStr, szPerformanceString, pszHashName, szSHA);
    }
    else
    {
        if (SFTP_MODE_PUT == Mode)
            printf ("Upload successful: %s -> %s (size %s, transfer: %s)\n", pszLocalFile, pszRemotePath, szNumStr, szPerformanceString);
        else if (SFTP_MODE_GET == Mode)
            printf ("Download successful: %s -> %s (size: %s, transfer: %s)\n", pszRemotePath, pszLocalFile, szNumStr, szPerformanceString);
    }

    rc = 0;

Done:

    if (pBuffer)
    {
        free (pBuffer);
        pBuffer = NULL;
    }

    if (pMdCtx)
    {
        EVP_MD_CTX_free (pMdCtx);
        pMdCtx = NULL;
    }

    if (fdLocal != -1)
        close (fdLocal);

    if (pHandle)
        libssh2_sftp_close (pHandle);

    if (pSftp)
        libssh2_sftp_shutdown (pSftp);

    if (pSession)
    {
        libssh2_session_disconnect (pSession, "done");
        libssh2_session_free (pSession);
    }

    if (nSock >= 0)
        close (nSock);

    libssh2_exit();
    return rc;
}


int sftp_put (const char *pszHost,
              uint16_t   nPort,
              uint16_t   nHash,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
              const char *pszExpectedHostKey)
{
    return sftp_transfer (SFTP_MODE_PUT,
                          pszHost,
                          nPort,
                          nHash,
                          pszUser,
                          pszPass,
                          pszLocalFile,
                          pszRemotePath,
                          pszExpectedHostKey);
}

int sftp_get (const char *pszHost,
              uint16_t   nPort,
              uint16_t   nHash,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
              const char *pszExpectedHostKey)
{
    return sftp_transfer (SFTP_MODE_GET,
                          pszHost,
                          nPort,
                          nHash,
                          pszUser,
                          pszPass,
                          pszLocalFile,
                          pszRemotePath,
                          pszExpectedHostKey);
}
