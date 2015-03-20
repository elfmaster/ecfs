
# ECFS

ECFS is an extension to the existing ELF core file format in Linux. 
Its job is to intercept the Linux core-dump handler, catch the core-dump
before it is written to disk, and carefully reconstruct it into an
ecfs-core file. An ecfs-core file is backwards compatible with regular
core files but has been extended in such a way that they boast prolific
amounts of data useful for process forensics analysis. An ecfs-file
is not limited to just ELF program headers, but also contains many section
headers as well as fully reconstructed relocation and symbol tables that
reflect the state of code and data in runtime. ecfs-core files are
also extremely straight forward to parse, moreso when using the
complementary libecfs C library (Python bindings are a work in progress).
See the manual page which describes how to access the different ecfs-core
components in-depth.


# USE CASES

ECFS creates high resolution snapshots of a running process. These 
snapshots are ideal for forensics analysis, and malware analysis. 
The libecfsreader API can be used to rapidly design advanced malware
analysis solutions for automated detection of threats within a process.
A brief example of this capability is demonstrated in POC||GTFO 0x7
https://www.alchemistowl.org/pocorgtfo/pocorgtfo07.pdf

IDA users will be happy to know that it is now possible to snapshot
an entire process and view the entire thing in IDA. It is important
to note that IDA does not understand that the shared library
functions are included in the actual ECFS file so it doesn't make
the connection reference between the calls to shared library functions
and their actual location within the file. It would be worth writing
a parser script for IDA to make this happen so you can click on a PLT
call and have it follow the GOT pointer right to the shared library
function. 

In addition to the malware analysis implications of ECFS, there is
an entirely different use case as well; ecfs-core snapshots can be
re-executed... that's right, you can snapshot a process and re-run
it later in time. Currently only a simple prototype exists for this
that I wrote up in about 4 hours: https://github.com/elfmaster/ecfs_exec

Enjoy...


## SYNOPSIS - Extended core file snapshot technology

This source code contains the ecfs suite of software which has several
components. The primary component plugs ecfs-core dump functionality 
into the Linux core dump routine. The secondary component being libecfs
which is a library specifically designed to parse ecfs-core files with
ease.

On 64bit Linux systems this software is also cross compiled for 32bit
so that a 32bit-handler can be dispatched in order to handle 32bit processes.
This requires that both 32bit and 64bit versions of libdwarf and libelf
be installed on your system simultaneously. On ubuntu systems libelf-dev 
package allows for this but libdwarf package does not. To get around
this you may link against the deps/libdwarf32.a and deps/libdwarf64.a 
files contained within. 

Once compiled and installed you will notice that /opt/ecfs/bin contains
these 3 files:

    /opt/ecfs/bin/ecfs_handler
    /opt/ecfs/bin/ecfs32
    /opt/ecfs/bin/ecfs64

The ecfs_handler is more or less a stub program that detects whether a process
is 32bit or 64bit, and then invokes the appropriate ecfs worker (ecfs32 or ecfs
64). ecfs-core files will be dumped in /opt/ecfs/cores and typically take up more
space (especially if -t option is being used) than regular core files. 
The main/readecfs.c utility is the equiavalent of what readelf is for regular
ELF files. readecfs parses and prints the details of an ecfs-core file to 
stdout. This utility uses libecfs as an example of how to use its
functions.

## INSTALL

The following are instructions on building and installing the ecfs-core dump 
software suite. Which includes not only the ecfs-core functionality itself, 
but also libecfs (For developers to parse ecfs-core files) and the readecfs 
utility (Similar to readelf). 

### Dependecies

#### Linux x86_64
(Note: deps/libdwarf32.a and deps/libdwarf64.a can be used)

    apt-get install libelf-dev libelf-dev:i386 libdwarf-dev

To build and install ecfs type:

    sudo ./setup.sh 
    sudo make install

Which is the equivalent to:

    make V=prod B=32
    make V=prod B=64
    sudo make install


The 'make install' will put custom line into /proc/sys/kernel/core_pattern 
that tells it to invoke /opt/ecfs/bin/ecfs_handler during a coredump.

!!! FOR UBUNTU USERS (AND POSSIBLY OTHER DISTROS) !!!
For Ubuntu the libdwarf package will not allow you to install it for
both 32bit and 64bit at the same time. To get around that simply follow
these instructions for building and installation.

sudo cp deps/libdwarf32.a /usr/lib
make V=prod B=32
sudo cp deps/libdwarf64.a /usr/lib
make V=prod B=64
sudo make install

#### Linux x86_32

For the 32bit systems we don't need ecfs_handler (Which invokes either a 32bit
or 64bit ./ecfs worker process). Only 32bit processes will be handled so
we can use the ./ecfs binary directly (Without ecfs_handler). Follow these
instructions:

Dependencies:

    apt-get install libelf-dev libdwarf-dev

To build and install ecfs type:

    sudo ./setup32.sh



## ECFS OPTIONS

### [-t option] text all option

This argument (Should generally be on) will direct the ecfs-core worker 
to write the entire text segment of each shared library (vs. just
the first 4k). ecfs ALWAYS writes the entire text segment of the executable
but limits the text of each shlib to only 4k unless you specify -t.
Which means opts.text_all is set in ecfs.c. Having -t set will cause
ecfs to take much longer as it has to write out sometimes hundreds of 
megabytes of code segments.

### [-h option] heuristics

ecfs can perform heuristics that do things such as mark shared libraries 
as being DLL injected. Sometimes false positives can arise. If you want 
to use the heuristics feature use the -h switch. As of 3/11/2015 there
are some bugs that need to be worked out in it, this README will change
once they are fixed, meanwhile I would recommend not using -h.


## Keeping ECFS enabled

Everytime you reboot you must run ./setup_core_pattern.sh to enable ecfs.
Unless you have setup ecfs to be permanent in your sysctl.conf file or
50-coredump.conf file as discussed below. On ubuntu systems the 'apport'
crash collector overrides the sysctl.conf with an init script, and a proper
install packge to override this behavior has not yet been created for ecfs
so it may be necessary to run setup_core_pattern.sh in ubuntu after every
reboot. You may check /proc/sys/kernel/core_pattern file to see ecfs has been
enabled.


To modify your sysctl.conf (For systems not using systemd)

    echo 'kernel.core_pattern=|/opt/ecfs/bin/ecfs_handler -t -e %e -p %p -o /opt/ecfs/cores/%e.%p' >> /etc/sysctl.conf


For systemd based systems such as ARCH Linux

Modify:

    /usr/libsysctl.d/50-coredump.conf

## ECFS CORE FILES

ecfs-core files will be dumped into /opt/ecfs/cores. These files take up
more space than a traditional core file, especially if you are using the -t
option which captures the entire text image of each loaded library. It may
be desirable to write a script that periodically compresses these files. 
The files are named according to the executable that crashed and the pid
like firefox.7737 if firefox pid 7737 were to crash, which makes them easy
to identify.

To read these files you may use any tools that you would use to analyze a 
regular ELF file with a few Caveats. They are backwards compatible with
regular core files but in order to analyze them with GDB you must flip
the e_type bit in the ELF file header from ET_NONE to ET_CORE. The
utility bin/et_flip will flip the bit to ET_CORE, and if you run it a 
second time on the file it will flip it back to ET_NONE. The reason
ecfs-core files are of type ET_NONE is because it allows the objdump
utility to utilize the section headers. If objdump sees that a file is 
of type ET_CORE it will assume it has no section headers and use the
program headers which aren't nearly as useful. 

Example:

    # et_flip sshd.26099 
    # gdb -q /usr/sbin/sshd sshd.26099
    Reading symbols from /usr/sbin/sshd...(no debugging symbols found)...done.
    [New LWP 26099]
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    Core was generated by `/usr/sbin/sshd -D'.
    Program terminated with signal SIGSEGV, Segmentation fault.
    #0  0x00007fcf37bbad83 in __select_nocancel () at ../sysdeps/unix/syscall-template.S:81
    81  ../sysdeps/unix/syscall-template.S: No such file or directory.
    (gdb) 

Now lets flip it back before using with objdump

    # et_flip sshd.26099 
    # objdump -d sshd.26099 | less
    sshd.26099:     file format elf64-x86-64

    Disassembly of section .init:

    00007fcf39c86c10 <.init>:
        7fcf39c86c10:       48 83 ec 08             sub    $0x8,%rsp
        7fcf39c86c14:       48 8b 05 65 e3 2a 00    mov    0x2ae365(%rip),%rax        # 7fcf39f34f80 <sub_7fcf39c88850-0x7fcf399ce8d0>
        7fcf39c86c1b:       48 85 c0                test   %rax,%rax
        7fcf39c86c1e:       74 05                   je     7fcf39c86c25 <sub_7fcf39c88850-0x7fcf39c7cc2b>
        7fcf39c86c20:       e8 bb 03 00 00          callq  7fcf39c86fe0 <sub_7fcf39c88850-0x7fcf39c7c870>
        7fcf39c86c25:       48 83 c4 08             add    $0x8,%rsp
        7fcf39c86c29:       c3                      retq   


The 'readecfs' utility is very handy very reading ecfs files and was 
specifically designed for this purpose. It is written using the libecfs 
API that also comes with this software-suite. For reading 64bit ecfs 
files use bin/prod/64/readecfs and use bin/prod/32/readecfs for 32bit.

## Example of readecfs

The readecfs has many command line options, but -e will show most of the ecfs s
pecific stuff.

    # readecfs -e host.25527

    - readecfs output for file cores/host.7628
    - Executable path (.exepath): /home/ryan/git/ecfs/ecfs_tests/host
    - Personality
        dynamically linked: yes
        compiled as PIE: no
        local symtab reconstruction: no
        malware heuristics: no
        original bin had stripped section headers: no

    - Thread count (.prstatus): 1
    - Thread info (.prstatus)
        [thread[1] pid: 7628

    - Register values
    r15:    0
    r14:    0
    r13:    7fff66b1bf40
    r12:    7fff66b1bae0
    rbp:    ffffffff
    rbx:    7fff66b1ba60
    r11:    246
    r10:    8
    r9:     0
    r8:     7fff66b1bb60
    rax:    fffffffffffffdfc
    rcx:    ffffffffffffffff
    rdx:    0
    rsi:    7fff66b1ba50
    rdi:    7fff66b1ba50
    rip:    7f3821a19f20
    rsp:    7fff66b1ba48
    cs:     33
    ss:     2b
    ds:     0
    es:     0
    fs:     0
    gs:     0
    eflags: 246
    - Exited on signal (.siginfo): 11
    - files/pipes/sockets (.fdinfo):
        [fd: 0] path: /dev/pts/8
        [fd: 1] path: /dev/pts/8
        [fd: 2] path: /dev/pts/8
        [fd: 3] path: /etc/passwd
        [fd: 4] path: /tmp/passwd_info

    - Printing shared library mappings:
    shlib:  libc-2.19.so.text
    shlib:  libc-2.19.so.undef
    shlib:  libc-2.19.so.relro
    shlib:  libc-2.19.so.data.0
    shlib:  ld-2.19.so.text
    shlib:  ld-2.19.so.relro
    shlib:  ld-2.19.so.data.1

    - Dynamic Symbol section -
    .dynsym:     -   7f3821959000
    .dynsym:    fputs -  7f38219c7730
    .dynsym:    __libc_start_main -  7f382197add0
    .dynsym:    fgets -  7f38219c7220
    .dynsym:    __gmon_start__ -     0
    .dynsym:    fopen -  7f38219c74e0
    .dynsym:    sleep -  7f3821a19d00

    - Symbol Table section -
    .symtab:     sub_4004b0 -    4004b0
    .symtab:     sub_400520 -    400520
    .symtab:     sub_40060d -    40060d
    .symtab:     sub_4006b0 -    4006b0
    .symtab:     sub_400720 -    400720

    - Printing out GOT/PLT characteristics (pltgot_info_t):
    gotsite            gotvalue          gotshlib          pltval
    0x601018           0x7f38219c7730     0x7f38219c7730     0x4004c6          
    0x601020           0x7f382197add0     0x7f382197add0     0x4004d6          
    0x601028           0x7f38219c7220     0x7f38219c7220     0x4004e6          
    0x601030           0x4004f6           0x0                0x4004f6          
    0x601038           0x7f38219c74e0     0x7f38219c74e0     0x400506          
    0x601040           0x7f3821a19d00     0x7f3821a19d00     0x400516          

    - Printing auxiliary vector (.auxilliary):
    AT_PAGESZ:   0x1000
    AT_PHDR:     0x400040
    AT_PHENT:    0x38
    AT_PHNUM:    0x9
    AT_BASE:     0x7f3821d1e000
    AT_FLAGS:    0x0
    AT_ENTRY:    0x400520
    AT_UID:  0x0
    AT_EUID:     0x0
    AT_GID:  0x0


# ECFS LOGGING/DEBUGGING

Debug output is logged using syslog() and can be found in either 
/var/log/syslog or on some systems such as arch Linux you will
need to look at 'journalctl -b'

elfmaster[at]zoho.com

