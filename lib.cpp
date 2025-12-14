
/* Copyright Nash!Com, Daniel Nashed 2024-2025 - APACHE 2.0 see LICENSE */

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

void strdncpy (char *pszStr, const char *ct, size_t n)
{
    if (NULL == pszStr)
        return;

    if (n>0)
    {
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wstringop-truncation"
        strncpy (pszStr, ct, n-1);
        #pragma GCC diagnostic pop
        pszStr[n-1] = '\0';
    }
}


void LogWarning (const char *pszErrorText)
{
    if (NULL == pszErrorText)
        return;

    fprintf (stderr, "Warning: %s\n\n", pszErrorText);
}


void LogInvalidOption (const char *pszCommand, const char *pszOption)
{
    struct  tm TimeTM = {0};
    ssize_t ret_size  = 0;
    FILE    *fp       = NULL;
    pid_t   ppid      = getppid();
    time_t  tNow      = time (NULL);

    char    szProcess[2048] = {0};
    char    szBinary[2048]  = {0};
    char    szExe[2048]     = {0};
    char    szTime[100]     = {0};

    if (NULL == pszOption)
        return;

    fprintf (stderr, "Warning - Unknown option: [%s]\n", pszOption);

    ret_size = readlink ("/proc/self/exe", szExe, sizeof (szExe));

    if (0 == ret_size)
        *szExe = '\0';

    fp = fopen ("/tmp/nshmailx.log", "a");

    if (NULL == fp)
        return;

    snprintf (szProcess, sizeof (szProcess), "/proc/%d/exe", ppid);
    ret_size = readlink (szProcess, szBinary, sizeof (szBinary));

    if (0 == ret_size)
        *szBinary = '\0';

    localtime_r (&tNow, &TimeTM);
    strftime (szTime, sizeof (szTime)-1, "%Y-%m-%d %H:%M:%S %z", &TimeTM);

    fprintf (fp, "%s exe: %s, ppid: %d, ppbin: %s, unknown option: %s [%s]\n", szTime, szExe, ppid, szBinary, pszCommand, pszOption);

    fclose (fp);
    fp = NULL;
}


void LogError (const char *pszErrorText, const char *pszParam)
{
    if (NULL == pszErrorText)
        return;

    if (pszParam)
        fprintf (stderr, "Error: %s: %s\n\n", pszErrorText, pszParam);
    else
        fprintf (stderr, "Error: %s\n\n", pszErrorText);

    ERR_print_errors_fp (stderr);
}

void LogError (const char *pszErrorText)
{
    LogError (pszErrorText, NULL);
}


bool GetUser (uid_t uid, size_t MaxReturnBuffer, char *retpszBuffer)
{
    struct passwd *pPasswd = NULL;

    if (MaxReturnBuffer && retpszBuffer)
        *retpszBuffer = '\0';
    else
        return false;

    pPasswd = getpwuid (uid);

    if (NULL == pPasswd)
        return false;

    if (NULL == pPasswd->pw_name)
        return false;

    strdncpy (retpszBuffer, pPasswd->pw_name, MaxReturnBuffer);
    return true;
}


size_t GetLocalHostname (char *retpszHostname, size_t MaxBuffer)
{
    if (NULL == retpszHostname)
        return 0;

    if (0 == MaxBuffer)
        return 0;

    if (gethostname (retpszHostname, MaxBuffer-1))
    {
        *retpszHostname = '\0';
        return 0;
    }

    return strlen (retpszHostname);
}

bool IsNullStr (const char *pszStr)
{
    if (NULL == pszStr)
        return 1;

    if ('\0' == *pszStr)
        return 1;

    return 0;
}


size_t GetFileSize (const char *pszFileName)
{
    int ret = 0;
    struct stat Filestat = {0};

    if (IsNullStr (pszFileName))
        return 0;

    ret = stat (pszFileName, &Filestat);

    if (ret)
        return 0;

    if (S_IFDIR & Filestat.st_mode)
        return 0;

    return Filestat.st_size;
}


int GetRandomString (const char *pszCharset, size_t len, char *retpszRandomString)
{
    const char    szDefaultCharset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unsigned char *p = (unsigned char *) retpszRandomString;

    size_t MaxIndex = sizeof (szDefaultCharset)-1;
    size_t i = 0;

    if (len <=0)
        return 1;

    if (NULL == retpszRandomString)
        return 1;

    /* Room for null terminator */
    len--;

    if (pszCharset)
        MaxIndex = strlen (pszCharset);
    else
        pszCharset = szDefaultCharset;

    /* Generate random bytes and use them as a modulo index to generate chars from charset specified */
    RAND_bytes ((unsigned char *) retpszRandomString, len);

    for (i=0; i < len; i++)
    {
        *p = *(pszCharset+ (*p % MaxIndex));
        p++;
    }

    *p = '\0';

    return 0;
}


int GetTimeString (time_t *pTime, char *retpszTime, size_t MaxBuffer)
{
    struct tm TimeTM = {0};

    if (MaxBuffer && retpszTime)
        *retpszTime = '\0';
    else
        return 1;

    gmtime_r (pTime, &TimeTM);
    strftime (retpszTime, MaxBuffer, "%a, %d %b %Y %H:%M:%S %z", &TimeTM);

    return 0;
}


void GetBytesHumanReadable (size_t bytes, size_t wMaxRetLen, char *retpNumberStr)
{
    double kb = bytes/1024.0;
    double mb = kb/1024.0;
    double gb = mb/1024.0;
    double tb = gb/1024.0;

    if(tb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%1.1f TB", tb);
        return;
    }

    if(gb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%1.1f GB", gb);
        return;
    }

    if(mb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%1.1f MB", mb);
        return;
    }

    if(kb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%1.1f KB", kb);
        return;
    }

    snprintf (retpNumberStr, wMaxRetLen, "%1.1f KB", kb);
}


void GetBytesHumanReadableAligned (size_t bytes, size_t wMaxRetLen, char *retpNumberStr)
{
    double kb = bytes/1024.0;
    double mb = kb/1024.0;
    double gb = mb/1024.0;
    double tb = gb/1024.0;

    if(tb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%6.1f TB", tb);
        return;
    }

    if(gb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%6.1f GB", gb);
        return;
    }

    if(mb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%6.1f MB", mb);
        return;
    }

    if(kb > 0.8)
    {
        snprintf (retpNumberStr, wMaxRetLen, "%6.1f KB", kb);
        return;
    }

    snprintf (retpNumberStr, wMaxRetLen, "%6.1f KB", kb);
}


int CalculatePerformanceString (size_t MSec, size_t Bytes, size_t wMaxRetLen, char *retpszPerformanceString)
{
    int    ret = 0;
    size_t BytesPerSec    = {0};
    char   szNumStr[1024] = {0};

    if (0 == wMaxRetLen)
        return 1;

    if (NULL == retpszPerformanceString)
        return 1;

    *retpszPerformanceString = '\0';

    if (0 == MSec)
        goto Done;

    BytesPerSec = (Bytes * 1000) / MSec;

    GetBytesHumanReadable (BytesPerSec, sizeof(szNumStr), szNumStr);

    snprintf (retpszPerformanceString, wMaxRetLen, "%s/sec", szNumStr);

Done:

    return ret;
}


long time_diff_ms (struct timespec start, struct timespec end)
{
    return (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
}

int FileExists (const char *pszFilename)
{
    int ret = 0;
    struct stat Filestat = {0};

    if (IsNullStr (pszFilename))
        return 0;

    ret = stat (pszFilename, &Filestat);

    if (ret)
        return 0;

    if (S_IFDIR & Filestat.st_mode)
        return 2;
    else
        return 1;
}


const EVP_MD *GetEvpMdFromHashLen (const char *pszHash)
{
    size_t len;
    size_t bits;

    if (IsNullStr (pszHash))
        return NULL;

    len = strlen (pszHash);

    /* hex string must be even length */
    if (len & 1)
        return NULL;

    /* 4 bits per hex character */
    bits = len * 4;

    switch (bits)
    {
        case 160:
            return EVP_sha1();

        case 256:
            return EVP_sha256();

        case 384:
            return EVP_sha384();

        case 512:
            return EVP_sha512();

        default:
            return NULL;
    }
}


size_t GetStringFromPrompt (const char *pszPrompt, size_t BufferLen, char *retpszPassword)
{
    size_t len = 0;
    char *p = retpszPassword;

    if ((NULL == retpszPassword) || (0 == BufferLen))
        return 0;

    retpszPassword[0] = '\0';

    if (IsNullStr (pszPrompt))
        return 0;

    fprintf (stdout, "%s: ", pszPrompt);
    fflush (stdout);

    if (!fgets (retpszPassword, BufferLen, stdin))
        return 0;

    while (*p)
    {
        if (*p < 32)
        {
            *p = '\0';
            break;
        }

        p++;
        len++;
    }

    return len;
}


size_t GetEnvironmentVar (const char *pszEnvName, size_t BufferLen, char *retpszPassword)
{
    const char *pszEnv = NULL;
    size_t len = 0;

    if ((NULL == retpszPassword) || (0 == BufferLen))
        return 0;

    retpszPassword[0] = '\0';

    if (IsNullStr (pszEnvName))
        return 0;

    pszEnv = getenv(pszEnvName);
    if (IsNullStr (pszEnv))
    {
        return 0;
    }

    snprintf (retpszPassword, BufferLen, "%s", pszEnv);
    len = strlen (retpszPassword);

    return len;
}


size_t GetStringFromFile (const char *pszFilename, size_t BufferLen, char *retpszPassword)
{
    FILE *fp   = NULL;
    size_t len = 0;
    size_t BufferLeft = 0;
    char szTemp[4096] = {0};

    char *p = szTemp;
    char *r = retpszPassword;

    if ((NULL == retpszPassword) || (0 == BufferLen))
        return 0;

    BufferLeft = BufferLen-1;

    retpszPassword[0] = '\0';

    if (IsNullStr (pszFilename))
        return 0;

    fp = fopen (pszFilename, "r");

    if (NULL == fp)
    {
        return 0;
    }

    if (!fgets(szTemp, sizeof (szTemp), fp))
    {
        goto Done;
    }

    while (*p)
    {
        if (0 == BufferLeft)
            break;

        if (*p < 32)
            break;

        *r = *p;

        p++;
        r++;
        len++;
        BufferLeft--;
    }

    *r = '\0';

    memset (szTemp, 0, sizeof(szTemp));

Done:

    if (fp)
    {
        fclose (fp);
        fp = NULL;
    }

    return len;
}


