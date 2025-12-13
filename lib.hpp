

#ifndef NSHMAILX_LIB_HEADER_HPP
#define NSHMAILX_LIB_HEADER_HPP


void strdncpy (char *pszStr, const char *ct, size_t n);
void LogWarning (const char *pszErrorText);
void LogInvalidOption (const char *pszCommand, const char *pszOption);
void LogError (const char *pszErrorText, const char *pszParam);
void LogError (const char *pszErrorText);
bool GetUser (uid_t uid, size_t MaxReturnBuffer, char *retpszBuffer);
size_t GetLocalHostname (char *retpszHostname, size_t MaxBuffer);
bool IsNullStr (const char *pszStr);
size_t GetFileSize (const char *pszFileName);
int GetRandomString (const char *pszCharset, size_t len, char *retpszRandomString);
int GetTimeString (time_t *pTime, char *retpszTime, size_t MaxBuffer);

#endif
