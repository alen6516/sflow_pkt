TOPDIR = ..

include $(TOPDIR)/rule.make

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
DEPENDS = $(patsubst %.c,%.d,$(SOURCES))

#$(OBJS): $(SRC)
#	$(CC) -c $(CFLAGS) -o $@ $<

.PHONY: all clean

all: a.out

clean:
	rm -f $(OBJECTS) $(DEPENDS) a.out

a.out: $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@

-include $(DEPENDS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@
