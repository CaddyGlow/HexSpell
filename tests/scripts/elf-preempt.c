/* Linux ELF acceptance fixture: RTLD_GLOBAL definition preempts an ordinary
 * default-visibility export when the generated image relocates a pointer. */
int answer(void) { return 99; }

/* Lifecycle arrays must use the same symbol-preemption policy as data pointers. */
int init_order;
int fini_order;
void init_1(void) { init_order = init_order * 10 + 1; }
void init_2(void) { init_order = init_order * 10 + 2; }
void fini_1(void) { fini_order = fini_order * 10 + 1; }
void fini_2(void) { fini_order = fini_order * 10 + 2; }
