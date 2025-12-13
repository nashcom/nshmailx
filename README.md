
# nshmail -- Simple SMTP mail send tool


This application can be used to troubleshoot and test SMTP connections.  
The application is based on OpenSSL and also show how to

- STARTTLS connections via OpenSSL
- Send SMTP mail crafting the RFC821 and RFC822 part of a message
- Lookup MX records and pick the one with the lowest priority value
- Create a simple MIME encoded mail with a base64 encoded attachment

## BSD mailx compatibility

In addition it is a replacement for the Linux BSD mailx command if only the sending part is required.

mailx supports sending and receiving and needs quite some packages installed including postfix or sendmail usually.
nshmailx in contrast is a single binary without additional package dependencies.
It also brings an admin into full control of the sending process.


## Syntax


```
Nash!Com SMTP Mail Tool 1.2.2
Copyright 2024-2025, Nash!Com, Daniel Nashed
OpenSSL 3.5.1 1 Jul 2025
(Build on: OpenSSL 3.5.1 1 Jul 2025)

Usage: nshmailx [Options]

-server <FQDN/IP>      SMTP server DNS name or IP (Can be a relay host. By default MX record of the recipient's domain is used)
-host <FQDN>           Hostname to send in EHLO (by default use server's hostname)
-port <number>         Port of SMTP server (Default: 25)
-from <email>          From address
-name <real name>      Name to add to the from address as a phrase
-to <email>            Send to recipient address
-cc <email>            Copy to recipient address
-bcc <email>           Blind copy to recipient address
-subject <text>        Subject of message
-body <text>           Body of message
-file <filepath>       File send as body (specify '-' to write stdin to the UTF-8 formatted body)
-att <filepath>        Attachment to send (specify '-' for attaching stdin to a file)
-attname <filename>    File name for file to attach
-mailer <name>         Mailer Name
-cipher <cipher list>  OpenSSL cipher list string (colon separated) used for a connection
-NoTLS                 Disable TLS/SSL
-NoTLS13               Disable TLS 1.3
-Verify                Verify TLS certificate
-v                     Verbose logging (specify twice for more verbose logging)
-silent                Only log errors to stderr
-trace                 Show input and output with client/server tags)
-pem                   Dump pem data with cert/key info (specify twice for PEM of certificate chain)
-encrypt               Encrypt message with S/MIME
-smime                 S/MIME file with PEM or raw Base64 DER certificate

-TestMessages          Number of test messages to send
-TestBodySize <bytes>  Bytes to sent for each test message body
-TestAttSize  <bytes>  Size of test attachment in bytes


SFTP Put Options (only supports user/password. for key authentication use scp)

-sftp <host>           Specify SFTP host name or IP
-user <username>       SFTP user name
-password <password>   user password
-att <filepath>        file to upload
-remote <filepath>     remote path
-hostkey <base64>      SSH compatible expected host key in Base64 without trailing =

Note: Also supports Linux BSD mailx command line sending options

Configuration file: /etc/nshmailx.cfg

from=<addr>            Standard from address
fromname=<addr>        Standard from name
mailer=<str>           Mail agent
hostname=<std>         Override default hostname
serveraddress=<addr>   Set server address/relay host
cipherlist=<list>      OpenSSL cipher list string (colon separated) used for a connection
rcptallowed=<regex>    Regex expression to define allowed recipients. Or specify 'file' for only allow entries from -reptfile
rcptfile=<file>        File name of recipients file (default: /etc/nshmailx.csv)
tls=0|1                Use TLS (enabled by default, can be disabled via tls=0
notls13=0|1            Disable TLS 1.3
verify=0|1             Verify certificate chain
ecdsa=0|1              Use ECDSA instead of RSA
utf8=0|1               Use UTF8
silent=0|1             Run silent. Only log errors to stderr

```

## Command Line Examples

### Send a simple mail

Mail with subject and body from command-line

```
./nshmailx -to nsh@acme.com -from nsh@acme.com -subject "Hello World ..." -body "This is a simple body text"
```

Mail with body from file /etc/os-release

```
./nshmailx -to nsh@acme.com -from nsh@acme.com -subject "Hello World ..." -file /etc/os-release
```


### Send a mail with stdin data attached to the mail

In this example the output of tar is packed into a file and named "notesdata.taz"

```
tar -cz /local/notesdata/*.ntf | ./nshmailx -to nsh@acme.com -from nsh@acme.com -subject "Notes Templates" -att - -attname notesdata.taz
```

### Fail2Ban sendmail command

Out of the box Fail2Ban uses sendmail. This command uses nshmailx to send mail instead.
Configuration file: `/etc/fail2ban/action.d/sendmail-common.conf`.


```
mailcmd = /usr/bin/nshmailx -from "<sender>" -to "<dest>" -file - -subject "Fail2Ban Report"
```


## Compile this application

This application is mainly intended for Linux and provides a Linux makefile.  
The main reason is that Linux provides an easy way to install OpenSSL development tools (openssl-devel) fitting your Linux version.  
It has been tested with OpenSSL 3.0.x

Once the compiler and the OpenSSL development package is installed just run `make`.


## Libs required for compiling

### Redhat/CentOS

dnf install openssl-devel libssh2-devel zlib-devel

### Ubuntu/Debian

apt install libssl-dev libssh2-1-dev zlib1g-dev
