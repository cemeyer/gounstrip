# Gounstrip

`gounstrip` parses out symbol address and name information from the
`.gopclntab` section of stripped Go ELF binaries and uses it to recreate a
rough symbol table (`.symtab`).  This can make it easier for reverse
engineering tools to associate code addresses with human-readable names.

## Usage

`gounstrip foo`

`foo` is modified in-place.  If you would like to be sure the file is not
corrupted, save a backup copy of `foo` first.

### Example

```
$ readelf -S foo
There are 13 section headers, starting at offset 0xNNNN:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
...
  [ 7] .gopclntab        PROGBITS         00000000NNNNNNNN  NNNNNNNN
       00000000NNNNNNNN  0000000000000000   A       0     0     32
...
  [12] .note.go.buildid  NOTE             00000000NNNNNNNN  0000NNNN
       000000000000NNNN  0000000000000000   A       0     0     4
...

$ ./gounstrip foo

$ readelf -S foo
There are 15 section headers, starting at offset 0xNNNN:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
...
  [ 7] .gopclntab        PROGBITS         00000000NNNNNNNN  NNNNNNNN
       00000000NNNNNNNN  0000000000000000   A       0     0     32
...
  [12] .note.go.buildid  NOTE             00000000NNNNNNNN  0000NNNN
       000000000000NNNN  0000000000000000   A       0     0     4
  [13] .strtab           STRTAB           0000000000000000  NNNNNNNN
       00000000NNNNNNNN  0000000000000000           0     0     1
  [14] .symtab           SYMTAB           0000000000000000  NNNNNNNN
       00000000NNNNNNNN  0000000000000018          13     0     8
...
```

## Caveats

No support is present for cross-endian binaries.  No support is present for
32-bit ELF binaries.  Needs some helper files from elftoolchain, which are not
distributed in library form, to compile and link.
