xtobjdis -- The ELF object file disassembler for the Xtensa ISA
===============================================================

**xtobjdis** is intended to read ELF object (.o) files containing code written for Xtensa (LX106) processors, and produce human-readable assembly output.

During disassembly, **xtobjdis** will perform a number of additional useful operations to try to make the resulting assembly code more readable/useful:

* Side-by-side assembly and hex output
* Automatic identification of code vs data regions.
* Application of ELF relocations and symbol lookup/resolution.
* Interpretation of Xtensa-specific ELF properties sections (.xt.prop and .xt.lit)
* Static code analysis to identify known register values, data accesses, literal values, evaluated expressions, etc.
* Determination (where possible) of data location sizes and types, identification of ASCII string data, alignment padding, etc.
* Various other miscellaneous annotations in the output assembly code.

Requirements
------------

In order to use **xtobjdis**, you will need to have the following installed on your system:

* [Python 3](https://www.python.org/downloads/) (currently.. I may add Py2 support at a later date.)

* The [pyelftools](https://pypi.python.org/pypi/pyelftools) python library:

        pip3 install pyelftools

* The [sortedcontainers](https://pypi.python.org/pypi/sortedcontainers) python library:

        pip3 install sortedcontainers

* xtensa-lx106-elf-objdump from a GNU Xtensa cross-compilation toolchain, or some equivalent Xtensa-compatible objdump program.  (If you happen to be working on ESP8266, I recommend the [esp-open-sdk](https://github.com/pfalcon/esp-open-sdk) project.)

If you want to make use of fixup files (`--fixups`), you will also need [PyYAML](http://pyyaml.org/) installed:

        pip3 install pyyaml

Usage
-----

The basic usage is as follows:

    xtobjdis input.o > output.s 

The object file specified will be disassembled and the result sent to stdout (which, as above, can be redirected to a file if desired).  There are a number of command options which can be used to change the output format, print additional info/debugging, etc.  For a list of those, use:

    xtobjdis --help

Note that you will need to have the **xtensa-lx106-elf-objdump** program in the same directory as xtobjdis, or somewhere on your path.  If your objdump is somewhere else, or is named something else, you can use the `--objdump=<cmd>` option (or the **XTOBJDIS_OBJDUMP** environment variable) to specify its location instead.

Note also that **xtobjdis** only supports disassembling ELF object (.o) files.  If you want to disassemble a library (.a) file, you will need to either split it out into its component .o files, or link it together into a single .o file containing all the contents first.  (Instructions for doing either of these will be printed by **xtobjdis** if you run it against an .a file directly.)

If you have a binary blob, you can disassemble it with objdump using the `--raw` and `--entrypoint` options.  Note that a large amount of the ELF meta-info xtobjdis has to work with will probably not be present in this case, so the result will likely not be as detailed (but should still be substantially better than a raw objdump).  The `--fixups` option can be used to add back some of this missing information, if it is known.

Limitations
-----------

**xtobjdis** should be fairly complete at this point, but there are a few areas that have not yet been implemented fully:

* **xtobjdis** should be fairly cross-platform, but to date it has only been tested under Linux.  There may be unexpected issues on other platforms (if you do try it on some other OS, please let me know how it goes).

* It currently only supports the call0 calling convention.  Windowed-register call opcodes (call4/call8/etc, entry, and so on) will be correctly disassembled, but function location identification, register value tracing, and opcode annotations may not be entirely correct if they are used.

* Some opcodes may not yet be fully implemented for register value tracing/etc. (I hope to finish checking all of these soon)

* **xtobjdis** should *theoretically* work for both little-endian and big-endian files, but it has thus far only been tested on little-endian inputs, so there may be some unexpected issues with big-endian inputs.

* There are several ways that a particularly pathological author/compiler could produce code which completely confuses the disassembler.  Some of these may be fixable with further improvements (others probably just aren't).  If you're disassembling code produced by something reasonably sane, however, you probably won't run into any of those cases.
