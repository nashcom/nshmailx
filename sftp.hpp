
/* Copyright Nash!Com, Daniel Nashed 2024-2025 - APACHE 2.0 see LICENSE */

#ifndef NSHMAILX_SFTP_HEADER_HPP
#define NSHMAILX_SFTP_HEADER_HPP

#define SFTP_MODE_PUT 1
#define SFTP_MODE_GET 2


#define SFTP_OPTIONS_PRINT_PROGRESS   0x0001

int sftp_put (const char *pszHost,
              size_t     nPort,
              size_t     nOptions,
              size_t     nHashAlg,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
	          const char *pszExpectedHostKey,
              const char *pszExpectedHash);

int sftp_get (const char *pszHost,
              size_t     nPort,
              size_t     nOptions,
              size_t     nHashAlg,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
              const char *pszExpectedHostKey,
              const char *pszExpectedHash);

#endif
