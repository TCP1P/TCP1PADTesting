// =============================================================================
// Armory — an intentionally vulnerable Attack & Defense PWN target.
//
// A menu-driven heap "item manager" served over TCP (one process per
// connection, via socat). It is riddled with classic memory-corruption bugs;
// EVERY one of them can be turned into a flag read, either by:
//   * redirecting control flow into print_flag() (no PIE, no canary), or
//   * flipping the global `admin` guard so option 8 (Secret) prints the flag, or
//   * directly executing a shell (option 7) to cat the flag file.
//
// The flag is read FRESH from $GZCTF_FLAG_FILE on each disclosure — never baked
// into the binary. Defenders patch the bugs (source or binary) while keeping
// the legitimate menu behaviour that the SLA checker exercises.
//
// BUG MAP:
//   #1  Stack buffer overflow ....... option 0 (Set nick): read() past a 32B stack buf
//   #2  Format string ............... option 6 (Echo): printf(user_buf)
//   #3  Use-after-free .............. option 4 (Delete) never NULLs -> options 2/3 reuse
//   #4  Double free ................. option 4 can free the same slot twice
//   #5  OOB array index ............. options 1/2/3/4 never bound-check `idx`
//   #6  Integer/sign issue in size .. option 1 (Add): size is a signed int into malloc()
//   #7  Heap overflow (bad length) .. option 3 (Edit): writes a caller-supplied length
//   #8  Command injection ........... option 7 (Ping): system("ping -c1 " + host)
//   #9  Backdoor win function ....... print_flag() reachable via #1/#2/#5
//   #10 Uninitialized heap leak ..... option 1 with size but no write -> option 2 leaks heap
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOTS 16

char *items[NSLOTS];
long  sizes[NSLOTS];
unsigned long admin = 0;            // #9 guard; print via Secret when == MAGIC
const unsigned long MAGIC = 0xC0DEFACEUL;

// --- flag disclosure -------------------------------------------------------
// The single place the flag is read; gated by the `admin` guard so the
// challenge has a clean "win" condition that several bugs can satisfy.
void print_flag(void) {
    char buf[128];
    const char *path = getenv("GZCTF_FLAG_FILE");
    if (!path) path = "/flag";
    FILE *f = fopen(path, "r");
    if (!f) { puts("FLAG: <unavailable>"); return; }
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    printf("FLAG: %s\n", buf);
}

// --- small IO helpers ------------------------------------------------------
static long read_long(void) {
    char line[32];
    if (!fgets(line, sizeof(line), stdin)) exit(0);
    return strtol(line, NULL, 10);
}

// Read exactly n bytes (used by Add). Caller controls n -> see bugs #6/#10.
static void read_n(char *buf, long n) {
    long got = 0;
    while (got < n) {
        long r = read(0, buf + got, n - got);
        if (r <= 0) break;
        got += r;
    }
}

// --- menu actions ----------------------------------------------------------

// #1 Stack buffer overflow: 32-byte stack buffer, reads up to 256 bytes. No
// stack canary / no PIE -> overwrite the saved return address to print_flag().
void set_nick(void) {
    char nick[32];
    printf("nick> ");
    fflush(stdout);
    read(0, nick, 256);                 // overflow
    printf("Hello, %.*s", 32, nick);
    puts("");
}

// #5 OOB index (no 0..NSLOTS check), #6 signed size into malloc(),
// #10 buffer is not zeroed and the write is optional.
void add_item(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();             // #5: unchecked
    printf("size> "); fflush(stdout);
    long size = read_long();            // #6: signed; negative -> huge size_t
    char *p = malloc(size);             // #10: not zeroed
    items[idx] = p;                     // #5: arbitrary slot (incl. OOB)
    sizes[idx] = size;
    printf("write> "); fflush(stdout);
    long wlen = read_long();            // optional / partial write -> #10 leak
    if (wlen > 0) read_n(p, wlen);
    printf("OK index=%ld\n", idx);
}

// #3 UAF / #5 OOB read: prints whatever items[idx] points at, even after free.
void show_item(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();             // #5: unchecked
    char *p = items[idx];
    if (!p) { puts("DATA: <empty>"); return; }
    printf("DATA: %.*s\n", (int)sizes[idx], p);  // #3 UAF read after delete
}

// #7 Heap overflow: writes a caller-supplied length into the existing buffer
// with no re-allocation and no bound to the original size.
void edit_item(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();             // #5
    char *p = items[idx];
    if (!p) { puts("ERR: empty"); return; }
    printf("len> "); fflush(stdout);
    long len = read_long();             // #7: unbounded vs allocation
    read_n(p, len);
    puts("OK edited");
}

// #4 Double free / #3 UAF: frees but never clears the slot pointer.
void del_item(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();             // #5
    free(items[idx]);                   // #4: callable twice on same slot
    puts("OK freed");                   // #3: items[idx] left dangling
}

void list_items(void) {
    printf("ITEMS:");
    for (int i = 0; i < NSLOTS; i++)
        if (items[i]) printf(" %d", i);
    puts("");
}

// #2 Format string: user buffer used as the format -> %p/%n leak & write,
// including overwriting `admin` to MAGIC.
void echo(void) {
    char buf[256];
    printf("msg> "); fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) exit(0);
    printf(buf);                        // format string
    fflush(stdout);
}

// #8 Command injection: host concatenated straight into a shell command.
void ping(void) {
    char host[128], cmd[256];
    printf("host> "); fflush(stdout);
    if (!fgets(host, sizeof(host), stdin)) exit(0);
    host[strcspn(host, "\n")] = '\0';
    snprintf(cmd, sizeof(cmd), "ping -c1 -W1 %s 2>&1", host);  // injection
    system(cmd);
}

// Backdoor disclosure, reachable by flipping `admin` via #1/#2/#5/#7.
void secret(void) {
    if (admin == MAGIC) {
        print_flag();
    } else {
        puts("Access denied.");
    }
}

void menu(void) {
    puts("=== Armory ===");
    puts("0) Set nick");
    puts("1) Add item");
    puts("2) Show item");
    puts("3) Edit item");
    puts("4) Delete item");
    puts("5) List items");
    puts("6) Echo");
    puts("7) Ping");
    puts("8) Secret");
    puts("9) Exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    while (1) {
        menu();
        switch (read_long()) {
            case 0: set_nick(); break;
            case 1: add_item(); break;
            case 2: show_item(); break;
            case 3: edit_item(); break;
            case 4: del_item(); break;
            case 5: list_items(); break;
            case 6: echo(); break;
            case 7: ping(); break;
            case 8: secret(); break;
            case 9: puts("bye"); return 0;
            default: puts("?"); break;
        }
    }
}
