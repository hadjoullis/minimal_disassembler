# minimal_disassembler
- minimal disassembler for ELF files
- works for both object and executable files
- only disassembles ELF sections which are expected to contain code
- if symbol table is available, then each function's code is differentiated 

## BUILDING
Install dependencies:
- libelf
- capstone

Run:
```
make
```
