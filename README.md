# Hash Password Module

Installation
------------
<blockquote>npm i opticore-hashing-password</blockquote>

<p align="center">

<a href="https://github.com/opticore-hashpassword/actions?query=workflow%3ATests+branch%3Amaster"><img src="https://github.com/opticore-hashpassword/workflows/Tests/badge.svg?branch=master" alt="GitHub Actions Build Status"></a></p>


Usage
-------------
<blockquote>import {HashPasswordService} from "opticore-hashing-password";</blockquote>

Exemple
-------------
```hash password
const passwordHash: HashPasswordService = new HashPasswordService();
const plainPassword: string = "password";
const salt: string = passwordHash.generateSalt(16, "hex");
const hashAlgorithm = 'argon2';
```

```hash password
Hash password
const hashedPassword = await passwordHash.hashPassword(plainPassword, salt, hashAlgorithm, 100, 4294, "hex");
```

```verify password
verify password
const isPasswordValid: boolean = await passwordHash.verifyHashPassword(hashedPassword, salt, plainPassword, hashAlgorithm, 100, 4294, "hex");
```

Notice
-------------
<blockquote>
You can use the RSA encrypt Password method, but you must first have an RSA key 
to pass it as a parameter. This method is not obligatory; 
it is just to increase the level of security
</blockquote>

<blockquote>
with argon2 as hash algorithm memoryCost get keyLength as parameter. So memory cost must be between 
1024 and 4,294,967,295. And those values represent RAM, so if you exceed your current RAM, your laptop
will crash, so careful. We suggest 1024 as keyLength value.
</blockquote>

Security Issues
---------------
https://github.com/guyzoum77/opticore-hashing-password/issues

Contributing
------------
OptiCore Hash Password module is an Open Source, so if you would like to contribute, you're welcome. Clone repository and open pull request.

About
--------
OptiCore Hash Password module is led by **Guy-serge Kouacou** and supported by **Guy-serge Kouacou**

