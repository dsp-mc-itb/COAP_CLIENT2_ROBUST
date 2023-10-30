/* minimal CoAP server
 *
 * Copyright (C) 2018-2023 Olaf Bergmann <bergmann@tzi.org>
 */

#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <coap3/coap.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#endif
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#endif
#include "common.c"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

static int quit = 0;
static int keep_persist = 0;
static const char *hint = "CoAP";
static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;
static void handle_sigint(int signum UNUSED_PARAM) { quit = 1; }
coap_resource_t *time_resource = NULL;

static coap_oscore_conf_t *oscore_conf;
static int doing_oscore = 0;

/* changeable clock base (see handle_put_time()) */
static time_t clock_offset;
static time_t my_clock_base = 0;

static int track_observes = 0;
/*
 * For PKI, if one or more of cert_file, key_file and ca_file is in PKCS11 URI
 * format, then the remainder of cert_file, key_file and ca_file are treated
 * as being in DER format to provide consistency across the underlying (D)TLS
 * libraries.
 */
static char *cert_file = NULL; /* certificate and optional private key in PEM,
                                  or PKCS11 URI*/
static char *key_file = NULL; /* private key in PEM, DER or PKCS11 URI */
static char *pkcs11_pin = NULL; /* PKCS11 pin to unlock access to token */
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM,
                                  DER or PKCS11 URI */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int use_pem_buf = 0; /* Map these cert/key files into memory to test
                               PEM_BUF logic if set */
static int is_rpk_not_cert = 0; /* Cert is RPK if set */
/* Used to hold initial PEM_BUF setup */
static uint8_t *cert_mem_base = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *key_mem_base = NULL; /* private key in PEM_BUF */
static uint8_t *ca_mem_base = NULL;   /* CA for cert checking in PEM_BUF */
/* Used for verify_pki_sni_callback PEM_BUF temporary holding */
static uint8_t *cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *key_mem = NULL; /* private key in PEM_BUF */
static uint8_t *ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t key_mem_len = 0;
static size_t ca_mem_len = 0;
static int verify_peer_cert = 1; /* PKI granularity - by default set */
#define MAX_KEY   64 /* Maximum length of a pre-shared key in bytes. */
static uint8_t *key = NULL;
static ssize_t key_length = 0;
int key_defined = 0;

static int support_dynamic = 0;
static int echo_back = 0;
static uint32_t csm_max_message_size = 0;
static size_t extended_token_size = COAP_TOKEN_DEFAULT_MAX;
static coap_proto_t use_unix_proto = COAP_PROTO_NONE;
static int enable_ws = 0;
static int ws_port = 80;
static int wss_port = 443;

static coap_dtls_pki_t *setup_pki(coap_context_t *ctx, coap_dtls_role_t role, char *sni);

static uint32_t block_mode = COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_TRY_Q_BLOCK;

#ifndef _WIN32
/*
 * SIGUSR2 handler: set quit to 1 for graceful termination
 * Disable sending out 4.04 for any active observations.
 * Note: coap_*() functions should not be called at sig interrupt.
 */
static void
handle_sigusr2(int signum COAP_UNUSED) {
  quit = 1;
  keep_persist = 1;
}
#endif /* ! _WIN32 */

static coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    ctx = coap_new_context(NULL);
    if (!ctx) {
        return NULL;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    s = getaddrinfo(node, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        coap_free_context(ctx);
        return NULL;
    }

    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t addr, addrs;
        coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL, *ep_tcp = NULL,
                        *ep_tls = NULL;

        if (rp->ai_addrlen <= sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
            addrs = addr;
            if (addr.addr.sa.sa_family == AF_INET) {
                uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
                addrs.addr.sin.sin_port = htons(temp);
            } else if (addr.addr.sa.sa_family == AF_INET6) {
                uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
                addrs.addr.sin6.sin6_port = htons(temp);
            } else {
                goto finish;
            }

            ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
            if (ep_udp) {
                goto finish;
            } else {
                coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
                continue;
            }
        }
    }

    fprintf(stderr, "no context available for interface '%s'\n", node);

finish:
    freeaddrinfo(result);
    return ctx;
}

static coap_binary_t *example_data_ptr = NULL;
static int example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;

static void
cache_free_app_data(void *data) {
  coap_binary_t *bdata = (coap_binary_t*)data;
  coap_delete_binary(bdata);
}

static void hnd_get_testing_q_block_init(coap_resource_t *resource,
                          coap_session_t *session,
                          const coap_pdu_t *request,
                          const coap_string_t *query COAP_UNUSED,
                          coap_pdu_t *response) {  
  uint8_t buf[4];
  coap_add_option(response, COAP_OPTION_Q_BLOCK2, coap_encode_var_safe(buf, sizeof(buf),(0 << 4|0 << 3|0)), buf);                          
  coap_pdu_set_code(response, COAP_RESPONSE_CODE(200));
}
#define NON_TIMEOUT (coap_fixed_point_t){1,0}
#define NON_RECEIVE_TIMEOUT ((coap_fixed_point_t){4,0})

static void hnd_put_image(coap_resource_t *resource,
                          coap_session_t *session,
                          const coap_pdu_t *request,
                          const coap_string_t *query COAP_UNUSED,
                          coap_pdu_t *response) {   
    printf("============ INCOMING REQUEST=============\n\n");    
    printf("\n");  
    coap_session_set_non_timeout(session,NON_TIMEOUT);
    coap_session_set_non_receive_timeout(session,NON_RECEIVE_TIMEOUT);
    size_t size;
    size_t offset;
    size_t total;
    const uint8_t *data; 
    coap_block_t block;
    coap_opt_t *option;
    coap_opt_iterator_t opt_iter;
    printf("Message Type : %x\n",coap_pdu_get_type(request));
    printf("Code : %x\n",coap_pdu_get_code(request));
    printf("Mid : %x\n",coap_pdu_get_mid(request));
    printf("Token : %x\n",coap_pdu_get_token(request));

     coap_option_iterator_init(request, &opt_iter, COAP_OPT_ALL);
        while ((option = coap_option_next(&opt_iter))) {
            printf("A: Option %d, Length %u\n",
             opt_iter.number, coap_opt_length(option));
        }
    // printf("Get Data : %x \n",coap_get_data_large(request, &size, &data, &offset, &total));
    // printf("get data : %s\n",data);
    
    
    //coap_pdu_set_code(response, COAP_RESPONSE_CODE(231));
  coap_binary_t *data_so_far;

  if (coap_get_data_large(request, &size, &data, &offset, &total) &&
    size != total) {
    /*
     * A part of the data has been received (COAP_BLOCK_SINGLE_BODY not set).
     * However, total unfortunately is only an indication, so it is not safe to
     * allocate a block based on total.  As per
     * https://tools.ietf.org/html/rfc7959#section-4
     *   o  In a request carrying a Block1 Option, to indicate the current
     *         estimate the client has of the total size of the resource
     *         representation, measured in bytes ("size indication").
     *
     * coap_cache_ignore_options() must have previously been called with at
     * least COAP_OPTION_BLOCK1 set as the option value will change per block.
     */
    coap_cache_entry_t *cache_entry = coap_cache_get_by_pdu(session,
                                                            request,
                                              COAP_CACHE_IS_SESSION_BASED);

    if (offset == 0) {
      if (!cache_entry) {
        /*
         * Set idle_timeout parameter to COAP_MAX_TRANSMIT_WAIT if you want
         * early removal on transmission failure. 0 means only delete when
         * the session is deleted as session_based is set here.
         */
        cache_entry = coap_new_cache_entry(session, request,
                                         COAP_CACHE_NOT_RECORD_PDU,
                                         COAP_CACHE_IS_SESSION_BASED, 0);
      }
      else {
        data_so_far = coap_cache_get_app_data(cache_entry);
        if (data_so_far) {
          coap_delete_binary(data_so_far);
          data_so_far = NULL;
        }
        coap_cache_set_app_data(cache_entry, NULL, NULL);
      }
    }
    if (!cache_entry) {
      if (offset == 0) {
        coap_log(LOG_WARNING, "Unable to create a new cache entry\n");
      }
      else {
        coap_log(LOG_WARNING,
                 "No cache entry available for the non-first BLOCK\n");
      }
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
      return;
    }

    if (size) {
      /* Add in the new data to cache entry */
      data_so_far = coap_cache_get_app_data(cache_entry);
      data_so_far = coap_block_build_body(data_so_far, size, data,
                                          offset, total);
      /* Yes, data_so_far can be NULL if error */
      coap_cache_set_app_data(cache_entry, data_so_far, cache_free_app_data);
    }
    if (offset + size == total) {
      /* All the data is now in */
      data_so_far = coap_cache_get_app_data(cache_entry);
      coap_cache_set_app_data(cache_entry, NULL, NULL);
    }
    else {
      /* Give us the next block response */
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTINUE);
      return;
    }
  }
  else {
    printf("get size : %d\n",size);
    printf("get offset : %d\n",offset);
    printf("get total : %d\n",total);
    /* single body of data received */
    data_so_far = coap_new_binary(size);
    if (data_so_far) {
      memcpy(data_so_far->s, data, size);
    }
  }

  if (example_data_ptr) {
    /* pre-existed response */
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
    coap_delete_binary(example_data_ptr);
  }
  else
    /* just generated response */
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);

  example_data_ptr = data_so_far;
  if ((option = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT,
                                  &opt_iter)) != NULL) {
    example_data_media_type =
            coap_decode_var_bytes (coap_opt_value (option),
                                   coap_opt_length (option));
  }
  else {
    example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;
  }

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
  coap_resource_notify_observers(resource, NULL);
    return;
    
}

static void init_resources(coap_context_t *ctx) {
    coap_resource_t *r;
    coap_resource_t *r2;

    r = coap_resource_init(coap_make_str_const("aaaaa"), resource_flags);
    coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_image);
    coap_resource_set_get_observable(r, 1);
    coap_add_resource(ctx, r);

    // r = coap_resource_init(coap_make_str_const("delay"), resource_flags);
    // coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_delay);
    // coap_add_resource(ctx, r);

    // r = coap_resource_init(NULL, resource_flags);
    // coap_register_handler(r, COAP_REQUEST_GET,hnd_get_q_block);
    // coap_add_resource(ctx, r);

    r2 = coap_resource_unknown_init(hnd_get_testing_q_block_init);
    coap_register_request_handler(r2, COAP_REQUEST_GET,hnd_get_testing_q_block_init);
    coap_add_resource(ctx, r2);

}

int main(int argc, char **argv) {
    coap_context_t *ctx = NULL;
    coap_tick_t now;
    char addr_str[NI_MAXHOST] = "::";
    char port_str[NI_MAXSERV] = "5683";
    int opt;
    //coap_log_t log_level = LOG_WARNING;
    coap_log_t log_level = 7;
    unsigned wait_ms;
    time_t t_last = 0;
    int coap_fd;
    fd_set m_readfds;
    int nfds = 0;
    uint16_t cache_ignore_options[] = { COAP_OPTION_BLOCK1,
                                      COAP_OPTION_BLOCK2,
                                      /* See https://rfc-editor.org/rfc/rfc7959#section-2.10 */
                                      COAP_OPTION_MAXAGE,
                                      /* See https://rfc-editor.org/rfc/rfc7959#section-2.10 */
                                      COAP_OPTION_IF_NONE_MATCH
                                    };
  #ifndef _WIN32
    struct sigaction sa;
  #endif

  while ((opt = getopt(argc, argv, "A:h:l:Np:v:")) != -1) {
        switch (opt) {
            case 'A':
                strncpy(addr_str, optarg, NI_MAXHOST - 1);
                addr_str[NI_MAXHOST - 1] = '\0';
                break;
            case 'h':
                if (!optarg[0]) {
                    // coap_log(LOG_CRIT, "Invalid PSK hint specified\n");
                    break;
                }
                hint = optarg;
                break;
            case 'l':
                if (!coap_debug_set_packet_loss(optarg)) {
                    usage(argv[0], LIBCOAP_PACKAGE_VERSION);
                    exit(1);
                }
                break;
            case 'N':
                resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_NON;
                break;
            case 'p':
                strncpy(port_str, optarg, NI_MAXSERV - 1);
                port_str[NI_MAXSERV - 1] = '\0';
                break;
            case 'v':
                log_level = strtol(optarg, NULL, 10);
                break;
            default:
                usage(argv[0], LIBCOAP_PACKAGE_VERSION);
                exit(1);
        }
    }
  /* Initialize libcoap library */
  coap_startup();
  coap_set_log_level(log_level);

  #ifdef _WIN32
    signal(SIGINT, handle_sigint);
  #else
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = handle_sigusr2;
    sigaction(SIGUSR2, &sa, NULL);
    /* So we do not exit on a SIGPIPE */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
  #endif

    ctx = get_context(addr_str, port_str);
    if (!ctx)
       return -1;
    
    init_resources(ctx);
    coap_context_set_block_mode(ctx,block_mode);
    
    coap_cache_ignore_options(ctx, cache_ignore_options,
             sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));

    coap_fd = coap_context_get_coap_fd(ctx);

    if (coap_fd != -1) {
        /* if coap_fd is -1, then epoll is not supported within libcoap */
        FD_ZERO(&m_readfds);
        FD_SET(coap_fd, &m_readfds);
        nfds = coap_fd + 1;
    }

    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

    while (!quit) {
        int result;
	
        if (coap_fd != -1) {
	
            fd_set readfds = m_readfds;
            struct timeval tv;
            coap_tick_t begin, end;
	        coap_ticks(&begin);
            tv.tv_sec = wait_ms / 1000;
            tv.tv_usec = (wait_ms % 1000) * 1000;
            result = select(nfds, &readfds, NULL, NULL, &tv); 

            if (result == -1) {

                if (errno != EAGAIN) {
                    coap_log(LOG_NOTICE, "select: %s (%d)\n",
                    coap_socket_strerror(), errno);
                    break;
                }
            }
            if (result > 0) {
		
                if (FD_ISSET(coap_fd, &readfds)) {
                    result = coap_io_process(ctx, COAP_IO_NO_WAIT);	
                }
            }
            if (result >= 0) {
		
               coap_ticks(&end);
               /* Track the overall time spent in select() and coap_io_process() */             
		result = (int)(end - begin);
            }
        } else {
            /* epoll is not supported within libcoap */
            result = coap_io_process( ctx, wait_ms );
        }
        if (result < 0) {
            break;
        } else if (result && (unsigned)result < wait_ms) {
	    
            /* decrement if there is a result wait time returned */
            wait_ms -= result;
	//printf("masuk minus re\n");
        } else {
	    //gettimeofday(&demoTime,NULL);
            //printf("Time TES F : %ld , %ld\n\n",demoTime.tv_sec,demoTime.tv_usec);
            /*
             * result == 0, or result >= wait_ms
             * (wait_ms could have decremented to a small value, below
             * the granularity of the timer in coap_run_once() and hence
             * result == 0)
             */

            wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
        }

         if (time_resource) {
             
            coap_time_t t_now;
            unsigned int next_sec_ms;

            coap_ticks(&now);
            t_now = coap_ticks_to_rt(now);
            if (t_last != t_now) {
            /* Happens once per second */
            t_last = t_now;
            coap_resource_notify_observers(time_resource, NULL);
            }
            /* need to wait until next second starts if wait_ms is too large */
            next_sec_ms = 1000 - (now % COAP_TICKS_PER_SECOND) *
                                 1000 / COAP_TICKS_PER_SECOND;
            if (next_sec_ms && next_sec_ms < wait_ms)
            wait_ms = next_sec_ms;
         }
      }

    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}