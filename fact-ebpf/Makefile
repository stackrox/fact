include ../constants.mk

format-check:
	find . \
		-iname 'vmlinux' -type d -prune -or \
		-type f \( -iname '*.h' -or -iname '*.c' \) -print \
	| xargs $(CLANG_FMT) -Werror --style=file -n

format:
	find . \
		-iname 'vmlinux' -type d -prune -or \
		-type f \( -iname '*.h' -or -iname '*.c' \) -print \
	| xargs $(CLANG_FMT) -Werror --style=file -i
