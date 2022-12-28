APP = bpf-link-helper

all: $(APP)

$(APP): $(APP).c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
