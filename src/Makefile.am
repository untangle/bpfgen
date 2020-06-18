AM_CPPFLAGS = ${LIBJSON_CFLAGS} 
AM_CFLAGS = ${LIBJSON_CFLAGS} 
AM_LDFLAGS = ${LIBJSON_LIBS}

bin_PROGRAMS = bpfgen
bpfgen_SOURCES = bpf_insn.h bpfgen_configuration.h bpfload.c bpfload.h \
                 imr.c imr.h main.c \
                 managers/imrManager.c managers/imrManager.h \
                 managers/imrManagerXdp.c managers/imrManagerXdp.h 
bpfgen_LDADD = ${LIBJSON_LIBS}
bpfgen_LDFLAGS = $(all_libraries) ${LIBJSON_LIBS}
