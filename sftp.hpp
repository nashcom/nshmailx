
#ifndef NSHMAILX_SFTP_HEADER_HPP
#define NSHMAILX_SFTP_HEADER_HPP

#define SFTP_MODE_PUT 1
#define SFTP_MODE_GET 2


#define SFTP_OPTIONS_PRINT_PROGRESS   0x0001

int sftp_put (const char *pszHost,
              size_t     nPort,
              size_t     nOptions,
              size_t     nHash,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
	      const char *pszExpectedHostKey);

int sftp_get (const char *pszHost,
              size_t     nPort,
              size_t     nOptions,
              size_t     nHash,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
              const char *pszExpectedHostKey);

#endif
