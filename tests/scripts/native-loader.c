/* Native generated-image acceptance. Build with cc -pthread [-ldl] native-loader.c. */
#if defined(__linux__) || defined(__APPLE__)
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unwind.h>

static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}
static void *symbol(void *image, const char *name) {
    dlerror();
    void *value = dlsym(image, name);
    const char *error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "dlsym %s: %s\n", name, error);
        exit(1);
    }
    return value;
}
static unsigned finalizer_order;
static void finalizer_callback(int value) {
    finalizer_order = finalizer_order * 10 + (unsigned)value;
}
#if defined(__APPLE__)
static void verify_exit_finalizers(void) {
    if (finalizer_order != 21) {
        fprintf(stderr, "process-exit finalizer order: %u (expected 21)\n", finalizer_order);
        _Exit(1);
    }
    puts("native loader acceptance passed");
}
#endif
static uint64_t *(*tls_address)(void);
static pthread_mutex_t tls_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t tls_condition = PTHREAD_COND_INITIALIZER;
static unsigned ready;
static uint64_t *tls_addresses[2];
static void *tls_thread(void *argument) {
    const uintptr_t index = (uintptr_t)argument;
    uint64_t *value = tls_address();
    if (*value != UINT64_C(0x11223344)) fail("incorrect thread-local initial value");
    *value = 100 + index;
    pthread_mutex_lock(&tls_lock);
    tls_addresses[index] = value;
    ready++;
    pthread_cond_broadcast(&tls_condition);
    while (ready != 2) pthread_cond_wait(&tls_condition, &tls_lock);
    if (tls_addresses[0] == tls_addresses[1]) fail("threads share TLS storage");
    pthread_mutex_unlock(&tls_lock);
    if (*value != 100 + index) fail("TLS value changed across threads");
    return NULL;
}
static uintptr_t unwind_begin;
static unsigned unwind_frames;
static int saw_generated_frame;
static _Unwind_Reason_Code visit_frame(struct _Unwind_Context *context, void *argument) {
    (void)argument;
    uintptr_t ip = (uintptr_t)_Unwind_GetIP(context);
    if (ip >= unwind_begin && ip < unwind_begin + 256) saw_generated_frame = 1;
    unwind_frames++;
    return _URC_NO_REASON;
}
static void unwind_callback(void) {
    _Unwind_Backtrace(visit_frame, NULL);
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "core") && strcmp(argv[1], "runtime"))) {
        fprintf(stderr, "usage: native-loader [core|runtime] IMAGE\n");
        return 2;
    }
#if defined(__APPLE__)
    /* Register before dlopen: dyld's later __cxa_atexit registrations run first. */
    if (!strcmp(argv[1], "runtime") && atexit(verify_exit_finalizers)) fail("atexit failed");
#endif
    void *image = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (image == NULL) fail(dlerror());
    int (*answer)(void) = (int (*)(void))symbol(image, "answer");
    int (*imported_pid)(void) = (int (*)(void))symbol(image, "imported_pid");
    int (**pointer)(void) = (int (**)(void))symbol(image, "answer_pointer");
    if (answer() != 42 || imported_pid() != (int)getpid() || (*pointer)() != 42)
        fail("import/export/relocated pointer check failed");
#if defined(__linux__)
    int (*versioned_answer)(void) = (int (*)(void))dlvsym(image, "answer", "HEXSPELL_1.0");
    if (versioned_answer == NULL || versioned_answer() != 42 ||
        dlvsym(image, "answer", "HEXSPELL_2.0") != NULL)
        fail("versioned export resolution check failed");
#endif
    if (*(uint64_t *)symbol(image, "initialized_marker") != UINT64_C(0x12345678) ||
        *(uint64_t *)symbol(image, "zero_marker") != 0)
        fail("initialized/zero-fill data check failed");
    if (!strcmp(argv[1], "runtime")) {
        if (*(uint64_t *)symbol(image, "init_marker") != 12)
            fail("constructor ordering check failed");
        tls_address = (uint64_t *(*)(void))symbol(image, "tls_address");
        pthread_t threads[2];
        for (uintptr_t i = 0; i != 2; i++)
            if (pthread_create(&threads[i], NULL, tls_thread, (void *)i)) fail("pthread_create failed");
        for (unsigned i = 0; i != 2; i++)
            if (pthread_join(threads[i], NULL)) fail("pthread_join failed");
        uint64_t *main_tls = tls_address();
        if (*main_tls != UINT64_C(0x11223344)) fail("main thread TLS was modified");
        void (*unwind_probe)(void (*)(void)) = (void (*)(void (*)(void)))symbol(image, "unwind_probe");
        unwind_begin = (uintptr_t)unwind_probe;
        unwind_probe(unwind_callback);
        if (!saw_generated_frame || unwind_frames < 3) fail("generated frame unwind failed");
        *(void (**)(int))symbol(image, "fini_callback") = finalizer_callback;
    }
    if (dlclose(image) != 0) fail(dlerror());
#if defined(__APPLE__)
    /* TLV libraries stay loaded; verify registered terminators at real process exit. */
    if (!strcmp(argv[1], "runtime")) return 0;
#endif
    if (!strcmp(argv[1], "runtime") && finalizer_order != 21) { fprintf(stderr,"finalizer order: %u (expected 21)\n",finalizer_order); fail("finalizer ordering check failed"); }
    puts("native loader acceptance passed");
    return 0;
}
