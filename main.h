#ifndef __MAIN_H
#define __MAIN_H

#define MAX_FILENAME_LEN 128

enum event_type {
    PROC_CREATE,
    PROC_EXIT,
    FILE_CREATE,
    FILE_OPEN,
    FILE_CLOSE,
};

struct event {
    enum event_type type;
    pid_t pid;
    char filename[MAX_FILENAME_LEN];
};

#endif