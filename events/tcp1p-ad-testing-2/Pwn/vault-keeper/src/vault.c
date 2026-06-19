// =============================================================================
// Vault Keeper — an intentionally vulnerable Attack & Defense PWN target.
//
// A menu-driven "secret vault" served over TCP (one process per connection,
// via socat). It has exactly ONE bug: delete() frees a note's data buffer and
// its metadata struct but never clears the slot pointer (`notes[idx] = NULL`),
// leaving the slot dangling. That use-after-free is enough for a full flag read.
//
// THE INTENDED EXPLOIT (UAF -> arbitrary read of the fixed-address flag):
//   1. create(0, 0x18, "A"*0x18)  -> malloc(data0) then malloc(struct0); both
//                                    land in tcache[0x20].
//   2. delete(0)                  -> free(data0); free(struct0). tcache[0x20]
//                                    LIFO head = struct0 -> data0. notes[0]
//                                    still dangles at struct0.
//   3. create(1, 0x18, payload)   -> the DATA malloc returns struct0 (the head)
//                                    and read_exactly writes `payload` INTO it.
//                                    payload = p64(128) + p64(&g_flag) + p64(0)
//                                    so struct0 becomes {size:128, data:&g_flag}.
//                                    (The struct malloc then returns data0;
//                                    notes[1] is irrelevant.)
//   4. show(0)                    -> reads dangling notes[0] (== struct0, now
//                                    {128, &g_flag}) -> DATA: <flag>.
//
// `&g_flag` is a fixed address (compiled -no-pie), resolvable from the binary's
// symbol table. The flag is read FRESH from $GZCTF_FLAG_FILE on each process
// start (one process per connection) — never baked into the binary.
//
// Defenders: add `notes[idx] = NULL;` after the frees in delete() (source or
// binary patch). That kills the UAF while keeping the create/show/edit/delete
// flow the SLA checker drives.
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOTS 8

struct note {
    unsigned long size;
    char *data;
};

struct note *notes[NSLOTS];   // global, all NULL initially

// Fixed-address global flag buffer (stable thanks to -no-pie). Read fresh on
// every process start so each connection sees the current planted flag.
char g_flag[128];

// --- flag loading ----------------------------------------------------------
static void load_flag(void) {
    const char *path = getenv("GZCTF_FLAG_FILE");
    if (!path) path = "/flag";
    FILE *f = fopen(path, "r");
    if (f) {
        size_t n = fread(g_flag, 1, sizeof(g_flag) - 1, f);
        g_flag[n] = '\0';
        fclose(f);
        // Trim a single trailing newline if present so the leak is clean.
        size_t len = strlen(g_flag);
        if (len && g_flag[len - 1] == '\n') g_flag[len - 1] = '\0';
    }
    if (g_flag[0] == '\0')
        strcpy(g_flag, "flag{warming-up}");
}

// --- small IO helpers ------------------------------------------------------
static long read_long(void) {
    char line[32];
    if (!fgets(line, sizeof(line), stdin)) exit(0);
    return strtol(line, NULL, 10);
}

// Read exactly n bytes. Reads of exactly N bytes consume precisely N bytes so
// the line-based menu stays aligned with the following choice line.
static void read_exactly(char *buf, long n) {
    long got = 0;
    while (got < n) {
        long r = read(0, buf + got, n - got);
        if (r <= 0) exit(0);
        got += r;
    }
}

// --- menu actions ----------------------------------------------------------

// 1 = create. Allocate the DATA buffer FIRST, then the struct (this ordering is
// what makes the UAF reallocation hand back struct0 in step 3 above).
static void create_note(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();
    if (idx < 0 || idx >= NSLOTS) { puts("ERR: bad index"); return; }
    printf("size> "); fflush(stdout);
    long size = read_long();
    if (size < 1 || size > 0x400) { puts("ERR: bad size"); return; }

    char *d = malloc(size);
    read_exactly(d, size);
    struct note *n = malloc(sizeof(struct note));
    n->size = size;
    n->data = d;
    notes[idx] = n;
    printf("OK index=%ld\n", idx);
}

// 2 = show. Write exactly notes[idx]->size bytes from notes[idx]->data. Does
// NOT verify the slot is still live — that is what makes the UAF observable.
static void show_note(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();
    if (idx < 0 || idx >= NSLOTS) { puts("ERR: bad index"); return; }
    if (!notes[idx]) { puts("ERR: empty"); return; }
    printf("DATA: "); fflush(stdout);
    write(1, notes[idx]->data, (size_t)notes[idx]->size);
    puts("");
}

// 3 = edit. Read exactly notes[idx]->size bytes into notes[idx]->data.
static void edit_note(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();
    if (idx < 0 || idx >= NSLOTS) { puts("ERR: bad index"); return; }
    if (!notes[idx]) { puts("ERR: empty"); return; }
    read_exactly(notes[idx]->data, (long)notes[idx]->size);
    puts("OK edited");
}

// 4 = delete. Free the data buffer then the struct.
// BUG: notes[idx] is never set to NULL -> the slot keeps dangling (UAF).
static void delete_note(void) {
    printf("index> "); fflush(stdout);
    long idx = read_long();
    if (idx < 0 || idx >= NSLOTS) { puts("ERR: bad index"); return; }
    if (!notes[idx]) { puts("ERR: empty"); return; }
    free(notes[idx]->data);
    free(notes[idx]);
    // BUG: missing `notes[idx] = NULL;` — the slot dangles. The defender's fix
    // is to add exactly that line here.
    puts("OK freed");
}

static void menu(void) {
    puts("=== Vault ===");
    puts("1) Create");
    puts("2) Show");
    puts("3) Edit");
    puts("4) Delete");
    puts("9) Exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    // Unbuffered stdio is REQUIRED: create/edit mix line reads (fgets) with raw
    // exact-byte read()s. Buffered stdin would read-ahead and swallow the data
    // bytes, desyncing the menu. Do NOT remove these.
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    load_flag();   // fresh per process (one process per connection)

    while (1) {
        menu();
        switch (read_long()) {
            case 1: create_note(); break;
            case 2: show_note();   break;
            case 3: edit_note();   break;
            case 4: delete_note(); break;
            case 9: puts("bye"); return 0;
            default: puts("?"); break;
        }
    }
}
