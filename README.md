# sendmailc
A minimalistic library to send emails with SMTP through Gmail and other popular services from C.

## Building on Linux
It's pretty simple, just run `make` and you'll get `libsendmailc.a` in the `lib` folder.
In your program you should `#include <sendmail.h>` and link to `-lsendmailc` and `-lcurl`.

## Crosscompiling for Windows with MinGW
Run `make CROSS_COMPILE=x86_64-w64-mingw32- BIN_SUFFIX=".exe" ADDITIONAL_LDFLAGS="-lws2_32"` and you'll get `libsendmailc.a` in the `lib` folder.
In your program you should `#include <sendmail.h>` and link to `-lsendmailc -lcurl -lws2_32`.

## Features
- [x] Sending simple emails with SMTP
- [x] Google OAUTH2
- [x] Google Gmail SMTP send support
- [ ] Microsoft OAUTH2
- [ ] Other SMTP servers
- [ ] Custom OAUTH2
- [ ] Other authentication schemes