# NC3 Christmas CTF

This CTF is created by NC3, the danish law enforcement cyber crime division.
The CTF has 4 challenges 1 each sunday in december and each have a week to
be solved.

This write-up is for the last challenge issued on the 24/12, this is the
most challenging of the four challenges according to the creators.

First we present the challenge (translated to english) and then we go through
the solution step by step.

The writeup is a bit comprehensive, which serve to give a bit of information about the process as well as explaining a bit about the steps used in gdb.

##  Challenge 4: Shh Shh!(Hard)

Friday morning at 7 am. professor Tournesol went to the laboratory where he worked.
Behind the desk with the softice-centrifuge he found a hemorrhaging professor Lennardo.
Lennardo was wounded and the perpetrator had escaped.

Before Lennardo drew his last breath, he managed to whisper a secret ciphertext:
`3,2,0,4,2,2,5,0,6,7,10,9,11,2,1,11,0,7,10,6,10,8,9,0,6,7,10,9,11,2,1,11`

And with his last strength he pointed towards the third drawer, which hid a USB media.
The drawer also contained a note, with the following message:

*"For security reasons, I have nulled the program."*

Tournesol found that the USB media contained a program which contained a message (the flag),
that could save the world!

[tys_tys](./tys_tys)


### Solution

First we take a brief look at the ciphertext and we can quickly see that it contains the integers from 0 to 11 that is 12 different characters and its 32 characters long.
We know the flags are on the form like: TH3_FLAG_IS_IN_THE_DETA1LS

From the look of it, we need to substitute the numbers with characters so we get the correct flag. We can make a few educated guesses, like 0 probably translates to _ as we can rule out 3,9,11,2 right away (characters in the start and end) and characters which repeat. The amount of 0 and its distribution in the ciphertext suggest its a space character or in our case the _ character.

Due to the l337speek alphabet used, we will stop guessing and go on with the binary program in [tys_tys](./tys_tys)

#### Program tys_tys

To check what binary we deal with we run the 'file' program on it, which will give us information we need fast.

`file ./tys_tys`

From this we find out that this file is a 64 bit dynamically linked and stripped ELF. That is a linux binary, without debug information.

Thats cool, cause we happen to be on a linux system!

Next step is to look for string constants inside the binary, we use the program *strings* for that.

`strings ./tys_tys`

Apart from constants we can also see which functions from libc the program use, this might give us some clues. We start with the functions and we can see it use (among others):

`strcpy, snprintf, connect, putchar, send, recv, gethostbyname, close`

Immediately we can see that the program likely connect to an ip address on the internet due to the use of gethostbyname, send, recv, connect.

We move further down in the results of the strings command and what we will look for is a hostname used by gethostbyname a format string used by snprintf and maybe some constants. Usualy these constants are grouped together.

Further down we find, what looks like an ip address: `45.63.119.180` and immediately after that a string `PRATEZ` and then `%s%s%s` which suggest a format string for the snprintf we found earlier.

We cant find any more intriguing stuff this way, so we move on with another great tool in the arsenal the program `strace`, which trace system calls and signals used by the program.

`strace ./tys_tys`

Towards the end of the listing we can see that the program use the connect call in order to connect to an ip address

`connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("45.63.119.180")}, 16) = 0`

Here we see the ip address, we discovered earlier and we also get the port number connected to, which is `4444`.

After this we see the following:
```
sendto(3, "?\n", 2, 0, NULL, 0)         = 2
recvfrom(3, "WND", 3, 0, NULL, NULL)    = 3
```

Which means the program send the sting `?\n` where \n is the newline character, to the receiving program at 45.63.119.180:4444.
The receiving program in turn send the string `WND` back.

Ok we did the initial recon, even before we ran the program, to get a view of what we deal with, but in order to figure out more intricacies we need to debug the binary to see the individual instructions. Running the program gives us 32 _ characters printed out and nothing else.

Enter gdb, the gnu debugger.

#### GDB reverse engineering

Before we fire up gdb and begin to reverse the binary, we make a dump of the assembler listing using `objdump`.

`objdump -D ./tys_tys > ./tys_tys.obj`

This way we have the whole assembly listing accessible while we work inside gdb.

Finaly we fire up gdb `gdb ./tys_tys` and at the prompt we issue the command `info file` this gives us some valuable information about the binary, here we look at the *entry point* which is 0x900
this will be the place we look at in our object dump.

To check the memory address we need to run the program first, enter `run` on the command prompt in gdb and after that `info file` then we get the absolute program entry point `0x555555554900`

You might get another address depending on your system.

When you run the program above you can see that it print out '________________________________' that is 32x _ , that is what we will look for in the object dump so we can work our way back from there to see if we get an idea of the inside workings.

We open the obj file and go to the address 0x900 and from there we browse to the end of the section, at address e00.

The first interesting thing we see is `callq  888 <putchar@plt>` at address d6f, we can see from the content of %edi, that the character printed is 0x0a, which is the newline character. This is the last thing the program prints out before the 32 _ characters.

If we move up in the object dump we get to the next putchar call and we can see that it is inside a loop where a local variable is compared to 0x1f (it runs from 0) so it prints 32 times.

Looking up further we can see that a bunch of local variables are nulled, which is probably what the good professor meant when he said he nulled the program.

We move further up in the listing untill we meet `callq  8b0 <snprintf@plt>` at address d14. This is a printf function that save the result in a variable, the format string for this is likely '%s%s%s' as discovered earlier.

We can confirm this by creating a breakpoint at d07
`break *0x555555554d07` and then inspecting the c string at the address contained in %rdx.
`info registers` is run and we get the value of rdx which in our case is `0x555555554e3c` and to print the c string at that address we issue the follwing command:

`print (char*) 0x555555554e3c`

And we get: `%s%s%s` as expected.

What we realy want tough is the result of the snprintf at address d14, so we create another breakpoint `break *0x555555554d0f` to get the value of %rdi, using `info registers`.

The address at %rid is `0x7fffffffe173` and will contain the cstring result of the snprintf.

We make the last breakpoint at d19 (so we know the snprintf is run) and we read the string at `0x7fffffffe173`.
`print (char*) 0x7fffffffe173` we get the result: `_L3WNDPRATEZ`.

We can see this string is 12 letters long, which correlate to the amount of unique integers in the ciphertext we discussed earlier. We can also see that the _ is the first letter aka the 0'th index of the string we just found.

If we assume that the character positions, starting from 0, of the string we just found correlate to the integers in the ciphertext like this:

0=>    _
1=>    L
2=>    3
3=>    W
4=>    N
5=>    D
6=>    P
7=>    R
8=>    A
9=>    T
10=>   E
11=>   Z

And we then substitute the integers in the ciphertext with the corresponding letter above, we get:

3,2,0,4,2,2,5,0,6,7,10,9,11,2,1,11,0,7,10,6,10,8,9,0,6,7,10,9,11,2,1,11
`W3_N33D_PRETZ3LZ_REPEAT_PRETZ3LZ`

Which is the flag to solve this challenge.
