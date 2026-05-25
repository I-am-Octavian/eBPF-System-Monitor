#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "main.skel.h"
#include "main.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static const char *event_type_str(enum event_type type)
{
	switch (type) {
	case PROC_CREATE:
		return "PROC_CREATE";
	case PROC_EXIT:
		return "PROC_EXIT";
	case FILE_CREATE:
		return "FILE_CREATE";
	case FILE_OPEN:
		return "FILE_OPEN";
	case FILE_CLOSE:
		return "FILE_CLOSE";
	}

	return "";
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (e->filename[0])
	{
		char* filename = strrchr(e->filename, '/');
		if(filename == NULL)
			filename = (char*)e->filename;
		else
			filename = filename + 1;
		printf("LLT007> %s %d %s\n", event_type_str(e->type), e->pid, filename);

	}
	else
		printf("LLT007> %s %d\n", event_type_str(e->type), e->pid);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct main_bpf *skel;
	int err;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = main_bpf__open();
	if (!skel) {
		return 1;
	}

	err = main_bpf__load(skel);
	if (err) {
		goto cleanup;
	}

	err = main_bpf__attach(skel);
	if (err) {
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	main_bpf__destroy(skel);
	return -err;
}