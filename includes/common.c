/* minimal CoAP functions
 *
 * Copyright (C) 2018-2023 Olaf Bergmann <bergmann@tzi.org>
 */


//int resolve_address(const char *host, const char *service, coap_address_t *dst);

static void usage(const char *program, const char *version) {
    const char *p;
    char buffer[64];

    p = strrchr(program, '/');
    if (p)
        program = ++p;

    fprintf(
        stderr,
        "%s v%s -- a small CoAP implementation\n"
        "(c) 2010,2011,2015-2018 Olaf Bergmann <bergmann@tzi.org> and "
        "others\n\n"
        "%s\n\n"
        "Usage: %s [-l loss] [-p port] [-v num]\n"
        "\t\t[-A address] [-N]\n"
        "\t\t[[-h hint]]\n"
        "General Options\n"
        "\t-l list\t\tFail to send some datagrams specified by a comma\n"
        "\t       \t\tseparated list of numbers or number ranges\n"
        "\t       \t\t(for debugging only)\n"
        "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
        "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
        "\t       \t\t(for debugging only)\n"
        "\t-p port\t\tListen on specified port\n"
        "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
        "\t       \t\tthere is increased verbosity in GnuTLS logging\n"
        "\t-A address\tInterface address to bind to\n"
        "\t-N     \t\tMake \"observe\" responses NON-confirmable. Even if set\n"
        "\t       \t\tevery fifth response will still be sent as a "
        "confirmable\n"
        "\t       \t\tresponse (RFC 7641 requirement)\n"
        "Image Options\n",
        program, version, coap_string_tls_version(buffer, sizeof(buffer)),
        program);
}