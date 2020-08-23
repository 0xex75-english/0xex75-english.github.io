---
title: "Bit flipping attack"
description: test.png
tags: ["Here we will explain what is behind the concept of bit flipping. A bit-flipping attack is an attack on a cryptographic cipher in which the attacker can modify the ciphertext in such a way as to cause a predictable change in the plaintext, although the attacker is not able to learn the text. in clear itself"]
---

Here we will explain what is behind the concept of bit flipping. A bit-flipping attack is an attack on a cryptographic cipher in which the attacker can modify the ciphertext in such a way as to cause a predictable change of the plaintext, although the attacker is not able to learn the text. in the clear itself.

I was confronted with a bit flipping on HTB in Lazy boxing, on a vulnerability of type `Padding Oracle` and I managed to get into the administrator account by changing only the bits of the` Cookie`, you will understand better afterwards.

# Theory

Each time you connect to a `website`, the server will give you a` Cookie`, for the simple reason that this simply allows a session to be maintained between the client and the server, if someone collects your cookies. , he would be able to connect to your account without putting the identifiers, that's why security is important!

# How the CBC works?

If your message that you want to encrypt is "hello", every time you encrypt the word "hello" it will always result in the same encrypted output. This poses a serious security risk because an attacker can carry out an attack by simply encrypting a list of words and then comparing them to the encrypted values, thereby revealing the token. The attacker can then create his own token, encrypt it and use it to log in as another user. CBC is a way to randomize the output of the encrypted value.

![forthebadge made-with-python](https://www.researchgate.net/profile/Mousa_Farajallah/publication/308826472/figure/fig1/AS:391837119467524@1470432657367/AES-encryption-system-in-CFB-mode.png)

The system is simple, the `CBC` encryption works by block, i.e. for a block to be` XORED`, it needs the previous block to be `XORED`.

    C¹ = E(P¹ ⊕ IV)
    Cⁿ = E(Pⁿ ⊕ Cⁿ - 1) — si n > 1

You will ask me the question, how can the first value of the block be encrypted, if it has no precedent?
This is where the `IV` system (Initialization vector) comes into play, it randomizes a random data so that it is XORED with the first block and so on until the last block, the formula below above summarizes the purpose.

So the attack is relatively simple, suppose we have a user named `admin` and the encryption of the` Cookie` is `21232f297a57a5a743894a0e4a801fc3`, our concrete goal is to change the` admin` value by changing only the bits of the `Cookie`, for example` vb232f297a57a5a743894a0e4a801fc3` which will become `bdmin`, the idea is there, it is to change the behavior of the` Cookie` and show it something else to access an account.

# Convenient

In my case, I will use a `XAMPP` server and install` Mullitidae`, Mullitidae is a `pentest` environment, feel free to [install] it (https://www.owasp.org/index.php/OWASP_Mutillidae_2_Project) to make interesting tests. Let's just start the `APACHE` and` MYSQL` service.

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/Capture.PNG?raw=true)

In version 2.6.10 of Mutilidae, there is a page called User Privilege Level. This is designed to practice the CBC bit flipping attack. You can find it under: OWASP 2013, Broken Authentication and Session Management, Privilege Scale, View User Privileges.

As you can see, the goal of this challenge is to change user and group to `000`. The first thing we need is the 'IV'. We need to use a proxy that sits between us and the server to intercept the communication between the `client` and the` server`. I will use `BurpSuite` for this. `BurpSuite` is a tool used to assist in the pentesting of web applications. you need to configure your browser to go through the Burp proxy. The configuration of the `BurpSuite` is out of scope for this station.

![forthebadge made-with-python](https://raw.githubusercontent.com/0xEX75/0xEX75.github.io/master/000.PNG)

Next, let's intercept the communication between client and server to tamper with the communication between client and server using `BurpSuite`.

If we change the first two values ​​to `FFc24fc1ab650b25b4114e93a98f1eba`, we will have an unintelligible thing output, which proves that we have power over the` Cookie`.

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/valeur.PNG)

    FFFF4fc1ab650b25b4114e93a98f1eba
    FFFFFFc1ab650b25b4114e93a98f1eba
    FFFFFFFFab650b25b4114e93a98f1eba
    FFFFFFFFFF650b25b4114e93a98f1eba
    FFFFFFFFFFFFFFFFb4114e93a98f1eba
    
If we change so on, we will have completely bypassed the standard output of the system. Ok, so we know the bit we need to change to change the part of the User ID field. Note this as we will need it later. Keep flipping the bits until you get to the part of the group ID that needs to be changed.

So the bits to modify are `6bc24fc1 FF 650b FF b4114e93a98f1eba`, this will give us the output:

![forthebadge made-with-python](https://raw.githubusercontent.com/0xEX75/0xEX75.github.io/master/0e.PNG)

So we found the bits we need to change to change the correct parts of the user and group ID. The next step is to modify them so that they return them as zero. We see that the user ID we sent to `FF` returned" e ". The FF we sent was a hex value and the "e" is a literal so the "e" needs to be converted to HEX. Use `Python` to decode" e "in HEX returns` 65`. Now we XORate `FF` with` 65`.

    $ import binascii
    $ binascii.hexlify(b'e')
    '65'
    $ print hex(0xff ^ 0x65)
    '0x9a'
    
The XORed value returns the HEX value `9a`. To get the value `0` completely, we need to convert` 0` to `HEX` which will give us` 30` and then `XOR` that value with` 9a`

    $ hex(0x30 ^ 0x9a)
    '0xaa'

So now the `Cookie` takes this form` 6bc24fc1 aa 650b FF b4114e93a98f1eba`, we are just missing the last `FF`, if we look through` BurpSuite`, we will see that the `000` is present, which means we are on the right track.

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/done.PNG?raw=true)

So we're on a problem, there's an unintelligible question mark, we need to find a value that can be readable, so let's try for example `31` that returns us a percentage, so we just have to convert` % `in HEX which will give us` 25`, then XOR `0x31` with` 0x25` (`0x14`) and finally` XOR` `0x30` with` 0x14`.

    $ import binascii
    $ binascii.hexlify(b'%')
    '25'
    $ print hex(0x31 ^ 0x25)
    0x14
    $ hex(0x30 ^ 0x14)
    '0x24'
    
Perfect, we are root, 6bc24fc1`aa`650b`24`b4114e93a98f1eba.

![forthebadge made-with-python](https://github.com/0xEX75/0xEX75.github.io/blob/master/root.PNG?raw=true)

# Conclusion

Here we are, we finally come to the end of this article which, I hope, will have you more. I tried to explain how the bit flipping technique works, don't hesitate to contact me on social media, I am always available to answer you.
