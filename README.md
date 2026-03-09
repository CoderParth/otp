You are trying to log in, and the website that you are trying to log in, asks you for your 6-digit one-time password. So, you grab your phone, open up your authenticator app to get your code, and sadly end up scrolling. Again. 

You could have saved yourself a lot of your productive time if you had not reached out for your phone; OTP solves this for you by providing you an authenticator on your terminal. 

In the long run, you are less likely to have issues with your computer (desktop/laptop) than with your phone, and in worst-case, you are also more likely to lose your phone than to lose your computer. In situations where you really need to login quickly, having an authenticator on your computer, or on an additional device, can make a huge difference. 


OTP is quite simple to use. When setting up 2FA, instead of scanning the barcode, click “enter the code manually”, and use OTP. Enter the code that you see on your screen, as a secret key, as shown in the example given below. 


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

