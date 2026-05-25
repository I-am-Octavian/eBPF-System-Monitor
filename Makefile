SUBDIR = libbpf-bootstrap/examples/c
TARGET_FILE = LLT007

all: $(TARGET_FILE)

$(TARGET_FILE):
	cp main.h $(SUBDIR)
	cp main.c $(SUBDIR)
	cp main.bpf.c $(SUBDIR)
	$(MAKE) -C $(SUBDIR)
	cp $(SUBDIR)/main .
	mv main $(TARGET_FILE)
	rm $(SUBDIR)/main.h
	rm $(SUBDIR)/main.c
	rm $(SUBDIR)/main.bpf.c

clean:
	$(MAKE) -C $(SUBDIR) clean
	rm -f $(TARGET_FILE)

.PHONY: all clean