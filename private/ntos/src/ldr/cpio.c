/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#include <stddef.h>
#include "cpio.h"

struct cpio_header_info {
    const char *filename;
    size_t filesize;
    void *data;
    struct cpio_header *next;
};

/* Parse an ASCII hex string into an integer. */
static size_t parse_hex_str(char *s, unsigned int max_len)
{
    size_t r = 0;
    size_t i;

    for (i = 0; i < max_len; i++) {
        r *= 16;
        if (s[i] >= '0' && s[i] <= '9') {
            r += s[i] - '0';
        }  else if (s[i] >= 'a' && s[i] <= 'f') {
            r += s[i] - 'a' + 10;
        }  else if (s[i] >= 'A' && s[i] <= 'F') {
            r += s[i] - 'A' + 10;
        } else {
            return r;
        }
        continue;
    }
    return r;
}

/*
 * Compare up to 'n' characters in a string.
 *
 * We re-implement the wheel to avoid dependencies on 'libc', required for
 * certain environments that are particularly impoverished.
 */
static int cpio_strncmp(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return a[i] - b[i];
        }
        if (a[i] == 0) {
            return 0;
        }
    }
    return 0;
}

/**
 * This is an implementation of string copy because, cpi doesn't want to
 * use string.h.
 */
static char* cpio_strcpy(char *to, const char *from) {
    char *save = to;
    while (*from != 0) {
        *to = *from;
        to++;
        from++;
    }
    return save;
}

static unsigned int cpio_strlen(const char *str) {
    const char *s;
    for (s = str; *s; ++s) {}
    return (s - str);
}

/* Calculate the remaining length in a CPIO file after reading a header. */
static size_t cpio_len_next(size_t len, void *prev, void *next) {
    size_t diff = (size_t) (next - prev);
    if (len < diff) {
        return 0;
    }
    return len;
}

/*
 * Parse the header of the given CPIO entry.
 *
 * Return -1 if the header is not valid, 1 if it is EOF.
 */
int cpio_parse_header(struct cpio_header *archive, size_t len,
		      struct cpio_header_info *info)
{
    const char *filename;
    size_t filesize;
    size_t filename_length;
    void *data;
    struct cpio_header *next;

    /* Ensure header is accessible */
    if (len < sizeof(struct cpio_header)) {
        return -1;
    }

    /* Ensure magic header exists. */
    if (cpio_strncmp(archive->c_magic, CPIO_HEADER_MAGIC, sizeof(archive->c_magic)) != 0) {
        return -1;
    }

    /* Get filename and file size. */
    filesize = parse_hex_str(archive->c_filesize, sizeof(archive->c_filesize));
    filename_length = parse_hex_str(archive->c_namesize, sizeof(archive->c_namesize));

    /* Ensure header + filename + file contents are accessible */
    if (len < sizeof(struct cpio_header) + filename_length + filesize) {
        return -1;
    }

    filename = (char *) archive + sizeof(struct cpio_header);
    /* Ensure filename is terminated */
    if (filename[filename_length - 1] != 0) {
        return -1;
    }

    /* Ensure filename is not the trailer indicating EOF. */
    if (filename_length >= sizeof(CPIO_FOOTER_MAGIC) && cpio_strncmp(filename,
                CPIO_FOOTER_MAGIC, sizeof(CPIO_FOOTER_MAGIC)) == 0) {
        return 1;
    }

    /* Find offset to data. */
    data = (void *) ((size_t) archive + sizeof(struct cpio_header) + filename_length);
    next = (struct cpio_header *) ((size_t) data + filesize);

    if (info) {
        info->filename = filename;
        info->filesize = filesize;
        info->data = data;
        info->next = next;
    }
    return 0;
}

/*
 * Get the location of the data in the n'th entry in the given archive file.
 *
 * We also return a pointer to the name of the file (not NUL terminated).
 *
 * Return NULL if the n'th entry doesn't exist.
 *
 * Runs in O(n) time.
 */
void *cpio_get_entry(void *archive, size_t len, int n, const char **name, size_t *size)
{
    struct cpio_header *header = archive;
    struct cpio_header_info header_info;

    /* Find n'th entry. */
    for (int i = 0; i <= n; i++) {
        int error = cpio_parse_header(header, len, &header_info);
        if (error) {
            return NULL;
        }
        len = cpio_len_next(len, header, header_info.next);
        header = header_info.next;
    }

    if (name) {
        *name = header_info.filename;
    }
    if (size) {
        *size = header_info.filesize;
    }
    return header_info.data;
}

/*
 * Find the location and size of the file named "name" in the given 'cpio'
 * archive.
 *
 * Return NULL if the entry doesn't exist.
 *
 * Runs in O(n) time.
 */
void *cpio_get_file(void *archive, size_t len, const char *name, size_t *size)
{
    struct cpio_header *header = archive;
    struct cpio_header_info header_info;

    /* Find n'th entry. */
    while (1) {
        int error = cpio_parse_header(header, len, &header_info);
        if (error) {
            return NULL;
        }
        if (cpio_strncmp(header_info.filename, name, -1) == 0) {
            break;
        }
        len = cpio_len_next(len, header, header_info.next);
        header = header_info.next;
    }

    if (size) {
        *size = header_info.filesize;
    }
    return header_info.data;
}

int cpio_info(void *archive, size_t len, struct cpio_info *info) {
    struct cpio_header *header;
    size_t current_path_sz;
    struct cpio_header_info header_info;

    if (info == NULL) return 1;
    info->file_count = 0;
    info->max_path_sz = 0;

    header = archive;
    while (1) {
        int error = cpio_parse_header(header, len, &header_info);
        if (error == -1) {
            return error;
        } else if (error == 1) {
            /* EOF */
            return 0;
        }
        info->file_count++;
        len = cpio_len_next(len, header, header_info.next);
        header = header_info.next;

        // Check if this is the maximum file path size.
        current_path_sz = cpio_strlen(header_info.filename);
        if (current_path_sz > info->max_path_sz) {
            info->max_path_sz = current_path_sz;
        }
    }

    return 0;
}

void cpio_ls(void *archive, size_t len, char **buf, size_t buf_len) {
    struct cpio_header *header;
    struct cpio_header_info header_info;

    header = archive;
    for (size_t i = 0; i < buf_len; i++) {
        int error = cpio_parse_header(header, len, &header_info);
        // Break on an error or nothing left to read.
        if (error) break;
        cpio_strcpy(buf[i], header_info.filename);
        len = cpio_len_next(len, header, header_info.next);
        header = header_info.next;
    }
}
