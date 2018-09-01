
CFLAGS = -fPIC -I.
LDLAGS = -linfo -L.

all:libinfo.a test

libinfo.a:sysinfo.o
	ar rcs $@ $^

test:test.o libinfo.a
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	-rm *.o *.a test