/*
 * Runs a libFuzzer target without libFuzzer: every file in the directory given as the only argument is passed to
 * LLVMFuzzerTestOneInput() in a buffer of exactly its size. tests/test_fuzz.py replays each corpus this way under
 * valgrind.
 */

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


static int
replay(const char *path)
{
    FILE     *f;
    long      n;
    uint8_t  *buf;

    f = fopen(path, "rb");
    if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        perror(path);
        return -1;
    }

    buf = malloc((size_t) n);   /* exactly the input: memcheck reports any read past it */
    if ((buf == NULL && n > 0) || fread(buf, 1, (size_t) n, f) != (size_t) n) {
        fprintf(stderr, "%s: read failed\n", path);
        return -1;
    }

    fclose(f);
    LLVMFuzzerTestOneInput(buf, (size_t) n);
    free(buf);

    return 0;
}


int
main(int argc, char **argv)
{
    DIR            *dir;
    char            path[4096];
    unsigned long   count = 0;
    struct dirent  *e;

    if (argc != 2 || (dir = opendir(argv[1])) == NULL) {
        fprintf(stderr, "usage: %s <corpus directory>\n", argv[0]);
        return 2;
    }

    while ((e = readdir(dir)) != NULL) {
        if (e->d_name[0] == '.') {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", argv[1], e->d_name);

        if (replay(path) != 0) {
            return 2;
        }

        count++;
    }

    closedir(dir);
    printf("replayed %lu inputs\n", count);

    return 0;
}
