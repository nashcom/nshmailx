
#ifndef NSHMAILX_SFTP_HEADER_HPP
#define NSHMAILX_SFTP_HEADER_HPP

#define SFTP_MODE_PUT 1
#define SFTP_MODE_GET 2

int sftp_put (const char *pszHost,
              uint16_t   nPort,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
	      const char *pszExpectedHostKey);

int sftp_get (const char *pszHost,
              uint16_t   nPort,
              const char *pszUser,
              const char *pszPass,
              const char *pszLocalFile,
              const char *pszRemotePath,
              const char *pszExpectedHostKey);

#endif
