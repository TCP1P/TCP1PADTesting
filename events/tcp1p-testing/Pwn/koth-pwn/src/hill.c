// =============================================================================
// Throne (pwn) — an intentionally vulnerable King-of-the-Hill "hill" binary.
//
// ONE shared container; served over TCP, one process per connection via socat.
// There is NO per-team flag. Teams take the hill by landing their per-round
// control TOKEN into the marker file the platform reads each tick:
//
//       /koth/king        (platform Trim()s it and matches it EXACTLY against
//                          the round token -> the file must equal the token)
//
// The only code that writes the marker is do_crown(), which writes the global
// `banner` buffer to /koth/king. Crowning legitimately needs `is_admin`, and
// no password is handed out — so taking the hill means exploiting a memory-
// corruption bug to either flip `is_admin` (then use option 6) or redirect
// control flow straight into do_crown() (no canary / no PIE). First set
// `banner` to your token, then trigger any bug below.
//
// BUG MAP (all lead to /koth/king := banner):
//   #1 Stack buffer overflow ... option 3 (Set nick): read() past a 64B buf
//                                -> overwrite saved RIP -> ret2 do_crown()
//   #2 Format string ........... option 4 (Echo): printf(buf) -> %n writes is_admin
//   #3 OOB array write ......... option 7/8 (Notes): unchecked idx -> write is_admin
//   #4 Use-after-free .......... option 9 then 7/8 (slot never NULLed)
//   #5 Double free ............. option 9 twice on one slot
//   #6 Heap overflow ........... option 8 (Edit): caller-supplied length, unbounded
//   #7 Auth backdoor ........... option 5 (Login): trivial/guessable check -> is_admin
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOTS 8
#define KING_FILE "/koth/king"

char  banner[256] = "set me to your round token";  // the string do_crown enthrones
int   is_admin = 0;                                 // crown guard (flip me)
char *notes[NSLOTS];
long  notesz[NSLOTS];

// The ONE writer of the marker. Writes `banner` atomically to /koth/king. The
// is_admin gate lives in the MENU, not here — so a ret2 do_crown() crowns
// regardless of is_admin (bug #1). Writes banner verbatim (no prefix) so the
// platform's Trim()+equality match on the token succeeds.
void do_crown(void) {
    char tmp[] = KING_FILE ".tmp";
    FILE *f = fopen(tmp, "w");
    if (!f) { puts("crown failed"); return; }
    fputs(banner, f);
    fclose(f);
    rename(tmp, KING_FILE);
    puts("the hill is yours");
}

static long read_long(void) {
    char line[32];
    if (!fgets(line, sizeof(line), stdin)) exit(0);
    return strtol(line, NULL, 10);
}

static void read_n(char *buf, long n) {
    long got = 0;
    while (got < n) {
        long r = read(0, buf + got, n - got);
        if (r <= 0) break;
        got += r;
    }
}

// Set the banner = the token you want enthroned (read up to 255 bytes, 1 line).
void set_banner(void) {
    printf("token> "); fflush(stdout);
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) exit(0);
    line[strcspn(line, "\n")] = '\0';
    strncpy(banner, line, sizeof(banner) - 1);
    banner[sizeof(banner) - 1] = '\0';
    puts("banner set");
}

void show_banner(void) {
    printf("banner: %s\n", banner);
}

// #1 Stack buffer overflow: 64-byte buf, reads 512. No canary / no PIE ->
// overwrite the saved return address with &do_crown.
void set_nick(void) {
    char nick[64];
    printf("nick> "); fflush(stdout);
    read(0, nick, 512);              // overflow
    printf("Hello, %.*s", 64, nick);
    puts("");
}

// #2 Format string: %n can write is_admin (its address is fixed; no PIE).
void echo(void) {
    char buf[256];
    printf("msg> "); fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) exit(0);
    printf(buf);                     // format string
    fflush(stdout);
}

// #7 Auth backdoor: a trivial, guessable check flips is_admin.
void login(void) {
    char pw[64];
    printf("password> "); fflush(stdout);
    if (!fgets(pw, sizeof(pw), stdin)) exit(0);
    pw[strcspn(pw, "\n")] = '\0';
    if (strcmp(pw, "letmein") == 0) {   // backdoor
        is_admin = 1;
        puts("welcome, admin");
    } else {
        puts("denied");
    }
}

// #3 OOB write / #4 UAF / #6 heap overflow live here. `idx` is never
// bound-checked, so add/edit can write a heap pointer (or is_admin) at an
// attacker-chosen index; edit's length is unbounded vs the allocation.
void add_note(void) {
    printf("idx> ");  fflush(stdout); long i = read_long();   // #3 unchecked
    printf("size> "); fflush(stdout); long n = read_long();
    char *p = malloc(n);
    notes[i] = p;                    // #3 OOB if i out of range
    notesz[i] = n;
    printf("data> "); fflush(stdout);
    read_n(p, n);
    puts("noted");
}

void edit_note(void) {
    printf("idx> "); fflush(stdout); long i = read_long();    // #3/#4 unchecked / dangling
    char *p = notes[i];
    if (!p) { puts("empty"); return; }
    printf("len> "); fflush(stdout); long n = read_long();    // #6 unbounded
    read_n(p, n);
    puts("edited");
}

void del_note(void) {
    printf("idx> "); fflush(stdout); long i = read_long();
    free(notes[i]);                  // #4 UAF (never NULLed) / #5 double free
    puts("freed");
}

// Legit crown: gated on is_admin (which the bugs above flip).
void crown(void) {
    if (is_admin) do_crown();
    else puts("denied: only the admin may crown");
}

void menu(void) {
    puts("=== King of the Hill: Throne ===");
    puts("1) Set banner (your token)");
    puts("2) Show banner");
    puts("3) Set nick");
    puts("4) Echo");
    puts("5) Login");
    puts("6) Crown");
    puts("7) Add note");
    puts("8) Edit note");
    puts("9) Delete note");
    puts("0) Exit");
    printf("> "); fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    while (1) {
        menu();
        switch (read_long()) {
            case 1: set_banner(); break;
            case 2: show_banner(); break;
            case 3: set_nick();   break;
            case 4: echo();       break;
            case 5: login();      break;
            case 6: crown();      break;
            case 7: add_note();   break;
            case 8: edit_note();  break;
            case 9: del_note();   break;
            case 0: puts("bye");  return 0;
            default: puts("?");   break;
        }
    }
}
