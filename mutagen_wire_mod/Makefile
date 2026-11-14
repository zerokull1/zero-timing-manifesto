all: mutagen_kern.o mutagen-ctl

mutagen_kern.o: mutagen_kern.c
	clang -O2 -g -target bpf -c mutagen_kern.c -o mutagen_kern.o

mutagen-ctl: mutagen-ctl.c
	gcc -O3 -s mutagen-ctl.c -o mutagen-ctl

clean:
	rm -f mutagen_kern.o mutagen-ctl
