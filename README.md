
You're trying to log in, and the website asks for your 6-digit one-time password. So you grab your phone, open your authenticator app — and end up scrolling. Again.

OTP solves this by bringing your authenticator to the terminal. No phone needed.

In the long run, your computer is less likely to fail you than your phone, and in a pinch, having an authenticator on an additional device can make all the difference.

## Getting started

Install with:

```
go install github.com/CoderParth/otp@latest
```

Then make sure your Go bin directory is on your PATH. Add this to your shell config (~/.bashrc, ~/.zshrc, etc.):
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Reload it:
```bash
source ~/.zshrc  # or ~/.bashrc
```

OTP is simple to use. When setting up 2FA, instead of scanning the QR code, click "enter the code manually" — then use that secret key with OTP, as shown in the example below.


### To add a new provider and a secret key:

Please follow the format below:
```
otp -add <provider> <your-secret-key>
```
Example:
```
otp -add github JBSWY3DPEHPK3PXP
```

***After completing the above process, feel free to set it up on your mobile phone as well.***


### To get your Time-based One-time password:

Please follow the format below:

```
otp <provider> 
```

Example:

```
otp github
```

Output:

```
729266 // Six-digit Time-based one-time password
```


