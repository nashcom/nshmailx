
#ifndef NSHMAILX_HEADER_HPP
#define NSHMAILX_HEADER_HPP


#define NSHMAILX_OPTIONS_NO_TLS            0x0001
#define NSHMAILX_OPTIONS_NO_TLS13          0x0002
#define NSHMAILX_OPTIONS_VERIFY            0x0004
#define NSHMAILX_OPTIONS_USE_ECDSA         0x0008
#define NSHMAILX_OPTIONS_NO_UTF8           0x0010
#define NSHMAILX_OPTIONS_ENCRYPT           0x0020
#define NSHMAILX_OPTIONS_HIGH_PRIO         0x0040
#define NSHMAILX_OPTIONS_LOW_PRIO          0x0080


int SendSmtpMessage (const char *pszHostname,
                     const char *pszMailer,
                     const char *pszSmtpServerAddress,
                     const char *pszFrom,
                     const char *pszFromName,
                     const char *pszSendTo,
                     const char *pszCopyTo,
                     const char *pszBlindCopyTo,
                     const char *pszSubject,
                     const char *pszBody,
                     const char *pszBodyFile,
                     const char *pszAttachmenFilePath,
                     const char *pszAttachmentName,
                     const char *pszAttachmentBuffer,
                     const char *pszCipherList,
		     const char *pszSmimeCert,
                     int  Port,
                     size_t Options);


#endif
