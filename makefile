EXE=det

SRCDIR=src
INCDIR=inc
BLDDIR=bld

SRCS=$(wildcard $(SRCDIR)/*.c)
OBJS=$(patsubst $(SRCDIR)%.c, $(BLDDIR)%.o, $(SRCS))

CFLAGS=-Wall -Wextra -fsanitize=leak,address,undefined

all: $(OBJS) libz0
	mkdir -p $(BLDDIR)
	$(CC) $(OBJS) -L$(BLDDIR) -l:libz0.a $(CLIBS) $(CFLAGS) -o $(BLDDIR)/$(EXE)

.PHONY:libz0
libz0: $(BLDDIR)/libz0.a
	$(MAKE) -C $@
	cp $@/$(BLDDIR)/$@.a $(BLDDIR)/

$(BLDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -I$(INCDIR) -Ilibz0/inc $(CFLAGS) -c $< -o $@

clean:
	rm $(OBJS)
