# Rizin Signature Database (Source)

This is the source database from which the .sig files in https://github.com/rizinorg/sigdb are generated.

Please commit only pat files in here and pat files needs to be reproducible.

# License

LGPL 3.0

## Mandatory folder structure:
```
<bin format>/<arch>/<bits>/<library>/<library>.pat
<bin format>/<arch>/<bits>/<library>/<library>.description
<bin format>/<arch>/<bits>/<library>/<library>.src.sha1
```

Where

- `<library>.pat` is the `pat` format to use to generate the final library (it is allowed to have other pat files in the folder).
- `<library>.description` is a human readable description of the library with max len of 1024 chars.
- `<library>.src.sha1` must contain the sha1 values of the original source file (deb, dll, etc..)
- `<bin format>` is the Rizin bin format name (use `rz-bin -L` to see the supported ones)
- `<arch>` is the Rizin architecture name (use `rz-asm -L` to see the supported ones)
- `<bits>` is the Rizin architecture bits (use `rz-asm -L` to see the supported ones based per architecture)


### Example generation of new library

```
# Find arch, bits and format
$ rz-asm -L | grep tricore
_dA_  32         tricore     GPL3    Siemens TriCore CPU
$ rz-bin -L | grep ELF
bin  elf         ELF format plugin (LGPL3)  

# Create folders and files
$ mkdir -p sigdb-source/elf/tricore/32/mylibrary
$ echo "My Library Description" > sigdb-source/elf/tricore/32/mylibrary.description
$ sha1sum my-tricore-lib.a > sigdb-source/elf/tricore/32/mylibrary.src.sha1

# Resolve automatically conflicts and generate the final pat file
$ python .scripts/generate-pat.py --auto --input /path/to/signature.pat --output sigdb-source/elf/tricore/32/mylibrary/mylibrary.pat
```

## Generate .sig files

```
$ mkdir build-sig
$ python .scripts/generate-sig.py --rz-sign /path/to/rz-sign --source /path/to/sigdb-source/ --output build-sig
```
