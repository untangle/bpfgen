AM_CPPFLAGS = ${LIBJSON_CFLAGS} 
AM_CFLAGS = ${LIBJSON_CFLAGS} 
AM_LDFLAGS = ${LIBJSON_LIBS}

bin_PROGRAMS = bpfgen
bpfgen_SOURCES = bpf_insn.h bpfgen_configuration.h bpfload.c bpfload.h imr.c imr.h imrManager.c imrManager.h main.c
bpfgen_LDADD = ${LIBJSON_LIBS}
bpfgen_LDFLAGS = $(all_libraries) ${LIBJSON_LIBS}
