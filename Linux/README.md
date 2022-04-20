# PoshC2 Native Linux implant

This folder contains code and installation scripts to build the PoshC2 native linux implant. 

## TODO

 - Other architectures (e.g. ARM)
 - Better configuration representation (e.g. integers as ints rather than strings)
 - Configuration obfuscation (if required - we don't have it in the python dropper atm.)
 
## Requirements

The runner needs to have gcc-multilib installed on it (for debian, `apt-get install gcc-multilib` should do the trick). 

## Versions

The versions of library compiled and installed are set in the variables section of the .gitlab-ci.yml file.

## Outputs

The script should result in a release and debug build of dropper and stage2core.so. 

The two that you want to use should be copied into the PoshC2 payload-templates folder where they will be updated with config by posh-server as appropriate.

Mixing debug and release dropper and stage2core files (e.g. debug dropper with release stage2core) hasn't been tested, but might work. 

## Local development

You'll need to install gcc-multilib, plus the build-essential metapackage (or equivalent for your distro).  

set the following variables (ensure the values match the values in the .gitlab-ci file):

```
export MUSL_VER=1.2.1
export UZLIB_VER=2.9.4
export MBED_VER=2.23.0
export LIBCURL_VER=7.71.1
```

You should then get away with just running install.sh from the repo root dir to build the libraries and do an initial build of the implant. 

If you then want to make changes to the implant code and not recompile all the libs you'll need to set the following environment variables:

```
PATH=$PATH:<path to bin containing musl-gcc>
LIB_DIR=<path to lib folder created in install.sh>
```

### Debugging

I've found gdb can get quite confused by the loading process so debugging the second stage can be a bit tricky at times. The debug builds are compiled with debug info, but it only tends to work for the dropper. 

If you want to produce something only in the debug build then use the DEBUG ifdef. 

There is also a `dprintf()` function defined, which will only be compiled in the debug build. This means that the release version doesn't have lots of debug strings lying around to help the reverse engineer :)

To use the `dprintf()` function you must specify two parameters  - i.e. a format string and some args. If you have no args then use `"%s"` as the first format string then your message as the second parameter. There's also a hexdump() function defined in common.h that you can use to dump out non-ascii values.

## Implant

### Goals

The aims of the implant are to be as portable as possible across x86/x86_64 linux distributions, without any specific dependancies on the target. It has been tested on kernels going back to 2.6 (but should work on 2.4), and works on some non-linux systems like ESXi. 

### Compilation

To make this as portable as possible we use musl instead of glibc and statically link everything so there are no dependancies on the target. We generate a 32 bit executable so it will work on x86 and x86_64 machines. 

The script first builds the libraries (MUSL, mbedtls, libcurl and uzlib) and then the implant. There are various hoops to jump through to get it to build and work correctly, this are 'documented' in the install.sh file. 

### Operation

The implant comes in two parts, a dropper and a stage2core. The dropper will have its config injected by PoshC2 (see below), and when run call into the C2 server to download the stage2. This will then be loaded into memory and executed without touching the disk.  

### Configuration

All configuration for the implant is contained in the dropper, except for a random key and uri which is patched into the stage2core when it is downloaded from the C2 server. 

The configuration is stored in an additional ELF section in the binary, as can be seen by running `readelf -S native_dropper`:

```
  [12] .bss              NOBITS          08149300 100300 003948 00  WA  0   0 32
  [13] .configuration    PROGBITS        0814cc48 103c48 0036e7 00  WA  0   0  1
  [14] .comment          PROGBITS        00000000 10732f 000029 01  MS  0   0  1
```

When the dropper is first compiled the .configuration section has a single byte length so we can reference its start in the code. To add in the configuration PoshC2 writes the configuration data to a temporary file and uses objcopy with the --update-section flag to replace the .configuration section with the contents of the file.

The configuration data is represented as a set of key value pairs, delimited by null bytes. For example:

```
...proxy_url=http://proxy.int\0proxy_user=joebloggs\0prox_pass=wednesday...

```
Any unknown keys are ignored. The configuration data must end with \0CONFIG_END\0 


### Dropper

The dropper is responsible for parsing the injected configuration and building a configuration struct which contains either parsed values (in the case of ints and floats) or pointers to strings (e.g. for strings like useragent etc.).

The dropper will establish a connection to the C2 server using the details provided and retrieve the stage2core.so file (into memory). This is required to be a statically linked relocatable shared object.

The dropper will then use the load_elf function to:
 - parse the stage2core's elf header
 - allocate memory as appropriate
 - copy segments into memory as required
 - carry out any relocations required 
 - adjust memory permissions
 - locate the 'loopy()' function symbol which is used as our entrypoint
 - locate and run the _init functions (these currently do nothing)
 - locate the __libc and __environ symbols, and set them as pointers to the dropper's values. This is because they contain values set by the kernel that I don't know how to initialise properly :)
 
The load_elf function returns the address of the loopy function where it is assigned to a function pointer. 

Because the second stage also needs to be statically linked, and needs to use the same libraries as the dropper, it seemed wasteful to also link it against e.g. libcurl. Therefore, a set of function pointers are constructed by the dropper and passed to the second stage as an argument, along with a pointer to the config struct built by parsing the .configuration section. This allows the second stage to use the libcurl functions linked in with the dropper without having to ship them down twice, and reduces the size of the second stage considerably. Along with the libcurl functions a pointer to the get_config_item function is also passed, this means that the second stage code doesn't need to be aware of the structure of the configuration.

To help the developer a set of defines are included in common.h for both config items (e.g. KEY) and the curl functions that are passed through in the function pointer array (there's some fairly complicated casting). It should be relatively straightforward to add new functions to the table by:
 - adding a typedef for the function call (e.g. `typedef CURLcode (*setopt)(CURL *curl, CURLoption option, ...);`) in common.h
 - create a define to make calling the function easier (e.g. `#define CURL_EASY_SETOPT(p1, p2, p3) ((setopt)(*_func_table[1]))(p1, p2, p3)`) in common.h - the offset here needs to match the order it's in the __func_table in the next step
 - add the function to the _func_table array in dropper.c (e.g. `(generic_fp)curl_easy_setopt,`)

This means that in the second stage  we can call curl_easy_setopt byt using CURL_EASY_SETOPT.

### Second stage

After all that, the second stage is relatively straightforward - it polls the C2 for commands and acts on them. Most of the parsing is carried out in process_single_cmd.

The most complex part is running the command with a shell, which is the default if we don't recognise any keywords such as 'download-file'. To do this, we:
 - Create a pair of non-blocking pipes
 - Fork the program
 - in the parent close the write end of the pipe
 - in the child close the read end of the pipe
 - in the child attach the write ends of the pipes to stdout and stderr
 - in the child exec() the command we've been given using /bin/sh
 - in the parent set an alarm (SIGALRM) for the value of process_timeout (default 120 seconds)

The parent will then read from the pipes until they close, and report the stdout and stderr back to the C2 server.

When the alarm timesout we first send SIGINT to the child, then SIGKILL. This is because some programs (like ping), won't produce all their output until they receive sigint so if you go straight in with kill then you'll not see the summary stats. Because we're executing a shell which is then executing our command we don't actually know the pid to kill at this point. To get around this after we've forked we set the process group of the child to be the same as its pid. This means that we can send the SIGINT and SIGKILL signals to the process group, and both the shell and its children will receive it. 

We also catch SIGCHILD so we can get the exit code of the process (e.g. to report if it exited with an error)


