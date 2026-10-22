/* Local reproduction of the allocation/sscanf pattern recovered from
 * libdialapm.so::parse_params(). It never connects to the TV. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *token = "malformed-token-without-an-equals-sign";
    size_t n = strlen(token);
    char *key = malloc(n);
    char *value = malloc(n);
    if (!key || !value) return 2;

    /* Recovered format string at .rodata+0x14f8: "%[^=]=%s". */
    int converted = sscanf(token, "%[^=]=%s", key, value);
    printf("token_len=%zu converted=%d key=%s\n", n, converted, key);
    free(value);
    free(key);
    return 0;
}
