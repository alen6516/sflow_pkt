TOPDIR = ..

include $(TOPDIR)/rule.make

SRC = main.c
OBJS = $(SRC:.c=.o)

$(OBJS): $(SRC)
	$(CC) -c $(CFLAGS) -o $@ $<

.PHONY: clean

clean:
	rm -f $(OBJS)
