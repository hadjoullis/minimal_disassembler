#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include <capstone/capstone.h>
#include <gelf.h>
#include <libelf.h>

void disas_file(csh handle, char *filename);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./disas.out <filename>\n");
        return EXIT_FAILURE;
    }

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        DIE("Unable to initialize csh handle");
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    disas_file(handle, argv[1]);

    cs_close(&handle);
    return EXIT_SUCCESS;
}

Elf_Scn *get_elf_section(Elf *elf, char *section) {

    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        DIE("(getshdrstrndx): %s", elf_errmsg(-1));

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr): %s", elf_errmsg(-1));

        if (strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), section) == 0) {
            return scn;
        }
    }

    return NULL;
}

void check_symtab(Elf *elf, fn_t **fns) {
    Elf_Scn *scn = get_elf_section(elf, ".symtab");
    if (scn == NULL) {
        *fns = NULL;
        return;
    }

    Elf_Data *data = NULL;
    data = elf_getdata(scn, NULL);

    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) != &shdr) {
        DIE("(getshdr): %s", elf_errmsg(-1));
    }

    int count = shdr.sh_size / shdr.sh_entsize;
    int fn_cnt = 0;

    for (int i = 0; i < count; i++) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
            fn_cnt++;
        }
    }

    *fns = malloc((fn_cnt + 1) * sizeof(fn_t));
    if (*fns == NULL) {
        DIE("fns malloc: %s", strerror(errno));
    }
    (*fns)[fn_cnt].fn_name = NULL;

    for (int i = 0, j = 0; i < count; i++) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
            (*fns)[j].addr = sym.st_value;
            (*fns)[j].fn_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            j++;
        }
    }
}

int is_fn(fn_t *fns, Elf64_Addr addr) {
    int i = 0;
    while (fns[i].fn_name != NULL) {
        if (fns[i].addr == addr) {
            return i;
        }
        i++;
    }
    return -1;
}

void print_insn(cs_insn insn, fn_t *fns) {
    int i;
    if (fns != NULL && (i = is_fn(fns, insn.address)) != -1) {
        fprintf(stderr, "\n%" PRIx64 " <%s>:\n", insn.address, fns[i].fn_name);
    }
    char bytes[BUF_LEN] = "";
    char temp[TEMP_LEN] = "";

    fprintf(stderr, "\t%" PRIx64 ": ", insn.address);
    for (i = 0; i < insn.size; i++) {
        sprintf(temp, "%02x ", insn.bytes[i]);
        strcat(bytes, temp);
    }
    fprintf(stderr, "%-30s\t%s\t%s\n", bytes, insn.mnemonic, insn.op_str);
}

void disas_section(csh handle, Elf_Scn *scn, Elf64_Addr addr, fn_t *fns) {
    Elf_Data *data = NULL;
    data = elf_getdata(scn, NULL);

    cs_insn *insn;
    size_t count;
    count = cs_disasm(handle, data->d_buf, data->d_size, addr, 0, &insn);
    if (count <= 0) {
        DIE("Failed to disassemble given code");
    }

    for (size_t j = 0; j < count; j++) {
        print_insn(insn[j], fns);
    }
    cs_free(insn, count);
}

void disas(csh handle, Elf *elf, fn_t *fns) {
    Elf_Scn *current_scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));
    }

    while ((current_scn = elf_nextscn(elf, current_scn)) != NULL) {
        if (gelf_getshdr(current_scn, &shdr) != &shdr) {
            DIE("(getshdr) %s", elf_errmsg(-1));
        }

        if ((shdr.sh_flags & SHF_EXECINSTR) == 0) {
            continue;
        }

        char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
        fprintf(stderr, "Disassembly of section %s:\n\n", name);
        disas_section(handle, current_scn, shdr.sh_addr, fns);
        fprintf(stderr, "\n");
    }
}

static int fd = -1;
static void cleanup(void) {
    int retval = close(fd);
    if (retval == -1) {
        perror("cleanup: close fd");
    }
}

void disas_file(csh handle, char *filename) {

    if (elf_version(EV_CURRENT) == EV_NONE) {
        DIE("(version): %s", elf_errmsg(-1));
    }

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        DIE("%s: %s", filename, strerror(errno));
    }
    atexit(cleanup);

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        DIE("(elf_begin): %s", elf_errmsg(-1));
    }

    fn_t *fns = NULL;
    check_symtab(elf, &fns);
    disas(handle, elf, fns);
}
