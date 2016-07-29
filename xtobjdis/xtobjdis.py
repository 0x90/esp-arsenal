#!/usr/bin/python3

#TODO: When literals are converted to relocptrs in raw mode, register value annotations are not updated to match.
#TODO: Add the ability to specify a data location explicitly as an address pointer
#TODO: windowed-call support
#TODO: better sorted data structure for section regions/annotations
#TODO: noabi switch
#TODO: check for non-emitted labels
#TODO: force anything found in "MS" sections to be interpreted as zero-terminated string data.
#TODO: make disassemble + assemble = original

import argparse
import sys
import os
import subprocess
import re
import struct
import bisect
import logging
import json
import hashlib

import elftools
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str, str2bytes
from elftools.elf.constants import *
from sortedcontainers import SortedDict

VERSION_STRING = '0.8'

OBJDUMP_ENV_VAR = 'XTOBJDIS_OBJDUMP'
DEFAULT_OBJDUMP = 'xtensa-lx106-elf-objdump'

# ELF relocation type constants for Xtensa (the ones we care about, at least)
R_XTENSA_NONE = 0
R_XTENSA_32 = 1
R_XTENSA_PLT = 6
R_XTENSA_ASM_EXPAND = 11
R_XTENSA_SLOT0_OP = 20

SECTION_FLAG_ATTRS = {
    'flag_alloc': (SH_FLAGS.SHF_ALLOC, 'a'),
    'flag_writable': (SH_FLAGS.SHF_WRITE, 'w'),
    'flag_exec': (SH_FLAGS.SHF_EXECINSTR, 'x'),
    'flag_mergeable': (SH_FLAGS.SHF_MERGE, 'M'),
    'flag_strings': (SH_FLAGS.SHF_STRINGS, 'S'),
    'flag_group': (SH_FLAGS.SHF_GROUP, 'G'),
    'flag_tls': (SH_FLAGS.SHF_TLS, 'T'),
}

OPCODE_INFO = {
    'call0': dict(
        slot0=0,
        type='call',
        clobber_regs=('a0', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11'),
    ),
    'callx0': dict(
        type='call',
        clobber_regs=('a0', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11'),
    ),
    'j': dict(
        slot0=0,
        type='branch',
        flow_break=True,
    ),
    'jx': dict(
        type='branch',
        flow_break=True,
    ),
    'ret': dict(
        flow_break=True,
    ),
    'rfe': dict(
        flow_break=True,
    ),
    'l32r': dict(
        slot0=1,
        type='literal',
    ),
    'movi': dict(
        slot0=1,
        type='move',
    ),
    'mov': dict(
        type='move',
    ),
    'addi': dict(
        slot0=2,
    ),
    'addmi': dict(
        slot0=2,
    ),
    'beqz': dict(
        slot0=1,
        type='branch',
        value_to_reg=False,
    ),
    'bnez': dict(
        slot0=1,
        type='branch',
        value_to_reg=False,
    ),
    'bgez': dict(
        slot0=1,
        type='branch',
        value_to_reg=False,
    ),
    'bltz': dict(
        slot0=1,
        type='branch',
        value_to_reg=False,
    ),
    'beqi': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bnei': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bgei': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'blti': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bgeui': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bltui': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bbci': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bbsi': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'beq': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bne': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bge': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'blt': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bgeu': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bltu': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bany': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bnone': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'ball': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bnall': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bbc': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'bbs': dict(
        slot0=2,
        type='branch',
        value_to_reg=False,
    ),
    'l8ui': dict(
        type='load',
    ),
    'l16si': dict(
        type='load',
    ),
    'l16ui': dict(
        type='load',
    ),
    'l32i': dict(
        type='load',
    ),
    's8i': dict(
        type='store',
        value_to_reg=False,
    ),
    's16i': dict(
        type='store',
        value_to_reg=False,
    ),
    's32i': dict(
        type='store',
        value_to_reg=False,
    ),
}

# The following opcodes should not appear inside a correct disassembly, so if
# we find them at the end, we've disassembled too far and will strip them off.
OPCODES_ILLEGAL = ('ill', '.byte')

OPCODE_ACCESS_WIDTH = {
    'l8ui':  1,
    'l16si': 2,
    'l16ui': 2,
    'l32i':  4,
    'l32r':  4,
    's8i':   1,
    's16i':  2,
    's32i':  4,
}

SIZE_NAMES = {
    1: 'byte',
    2: 'hword',
    4: 'word',
}

# Minimum number of zero bytes we look for between nonzero sequences to
# consider the zeros to be their own padding region.
MIN_PADDING_REGION = 16

# The minimum number of ASCII characters we look for to determine if the data
# at a particular location should be represented as .ascii/.asciz in the output
# instead of .byte
MIN_ASCII_LEN = 5

# Flag constants used by .xt.prop sections
XTENSA_PROP_LITERAL            = 0x00000001
XTENSA_PROP_INSN               = 0x00000002
XTENSA_PROP_DATA               = 0x00000004
XTENSA_PROP_UNREACHABLE        = 0x00000008
XTENSA_PROP_INSN_LOOP_TARGET   = 0x00000010
XTENSA_PROP_INSN_BRANCH_TARGET = 0x00000020

# Logging setup and utility routines

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

info_level = 0
debug_level = 0

def info(level, msg, *args, **kwargs):
    if level <= info_level:
        log.info(msg, *args, **kwargs)

def debug(level, msg, *args, **kwargs):
    if level <= debug_level:
        indent = ' ' * max(0, level - 1)
        log.debug(indent + msg, *args, **kwargs)

def debug_regs(level, msg, regs, *args, **kwargs):
    if level <= debug_level:
        if regs:
            regstr = ', '.join('{}={}'.format(k,v) for k,v in sorted(regs.items()) if v is not None)
        else:
            regstr=str(regs)
        indent = ' ' * level
        log.debug(indent + msg + regstr, *args, **kwargs)

# Miscellaneous utility functions

def is_pathname(filename):
    "Determine whether the filename has directory components in it or not"
    if os.sep in filename:
        return True
    if os.altsep and os.altsep in filename:
        return True
    return False

def os_path():
    "Return the OS's search path as a list"
    path = os.environ.get('PATH', os.defpath)
    return [d or os.curdir for d in path.split(os.pathsep)]

def is_zeroes(data):
    for b in data:
        if b != 0:
            return False
    return True

ASCII_CHARS = {10, 13} | set(range(0x20, 0x7f))

def is_ascii_data(start, end, no_extra=True):
    section = start.section
    start_offset = start.offset
    end_offset = end.offset
    for i in range(start_offset, end_offset):
        c = section.data[i]
        if c in ASCII_CHARS:
            continue
        if c == 0 and i != start_offset:
            # We ran into a null byte.  This may just be termination/padding at
            # the end of the string, which is fine.
            if no_extra:
                # Make sure everything from here to the end is all zeroes,
                # though.
                if not is_zeroes(section.data[i:end_offset]):
                    return False
            # Return a length including the first zero-byte (assuming this
            # is an asciiz string).
            return i - start_offset + 1
        return False
    return end - start

def _as_string_literal_cb(m):
    c = ord(m.group(0))
    lookup = {0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r', 0x5c: '\\\\', 0x22: '\\"'}
    return lookup.get(c, '\\x{:02x}'.format(c))

def as_string_literal(string):
    "Return the string as a string-literal appropriate for GNU as source code"
    return '"' + re.sub('[\x00-\x1f"\\\\]', _as_string_literal_cb, string) + '"'

def flush(i):
    "Read all the data from an iterator until it's finished."
    try:
        while True:
            next(i)
    except StopIteration:
        pass

# Exceptions

class XtobjdisException (Exception):
    pass


class NoSymTabException (XtobjdisException):
    pass


class DisassemblyFailedException (XtobjdisException):
    pass


# Main code starts here

class Opcode:
    def __init__(self, addr, length, instr, args):
        self.addr = addr
        self.length = length
        self.instr = instr
        self.args = args
        self.notes = []
        self.regs = None
        self.regs_resolved = False
        self.value = None
        self.dest_addr = None
        try:
            offset = addr.offset
            self.data = addr.section.data[offset:offset+length]
        except IndexError:
            self.data = b''

    def argstr(self):
        return ', '.join(str(a) for a in self.args)

    def tostr(self):
        return self.instr + ' ' + self.argstr()

    def hexdata(self):
        return ''.join('{:02x}'.format(b) for b in self.data)

    def add_note(self, note):
        self.notes.append(note)

    def __repr__(self):
        return '<{}+0x{:x}: {} {}>'.format(self.section.name, self.addr, self.instr, self.argstr())


class Addr:
    def __init__(self, section, offset, name=None, base=None):
        if not isinstance(offset, int):
            raise ValueError("Offset ({!r}) is not an integer".format(offset))
        self.section = section
        self.offset = offset
        self.name = name
        self.base = base

    def loc_str(self):
        if self.base:
            base_name = self.base.name
            base_offset = self.base.offset
        elif self.section:
            base_name = self.section.name
            base_offset = 0
        else:
            return '<null symbol>'
        if self.base and self.offset == base_offset:
            return base_name
        elif self.offset >= base_offset:
            return '{}+0x{:x}'.format(base_name, self.offset - base_offset)
        else:
            return '{}-0x{:x}'.format(base_name, base_offset - self.offset)

    def target_str(self):
        if self.name:
            return self.name
        if self.section:
            labels = self.section.get_labels(self.offset)
            if labels:
                return sorted(labels)[0]
        if self.base and self.offset == self.base.offset:
            return self.base.name
        return self.loc_str()

    def __repr__(self):
        loc_str = self.loc_str()
        target_str = self.target_str()
        if loc_str != target_str:
            return '<{} ({})>'.format(loc_str, target_str)
        else:
            return '<{}>'.format(loc_str)

    def __str__(self):
        return self.target_str()

    def __int__(self):
        return self.offset

    __index__ = __int__

    def __add__(self, other):
        if isinstance(other, Addr):
            raise ValueError("Cannot add two addresses ({!r} and {!r}).  Can only add one address and an offset".format(self, other))
        else:
            base = self.base
            if not base and self.name:
                base = self
            return Addr(self.section, self.offset + int(other), base=base)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, Addr):
            if self.section == other.section:
                return self.offset - other.offset
            else:
                raise ValueError("Attempt to subtract addresses in two different sections ({!r} - {!r})".format(self, other))
        else:
            base = self.base
            if not base and self.name:
                base = self
            return Addr(self.section, self.offset - int(other), base=base)

    def __lt__(self, other):
        if not isinstance(other, Addr):
            return NotImplemented
        if self.section != other.section:
            raise ValueError("Arithmetic comparison of addresses in different sections is not defined ({!r} vs {!r})".format(self, other))
        return self.offset < other.offset

    def __gt__(self, other):
        if not isinstance(other, Addr):
            return NotImplemented
        if self.section != other.section:
            raise ValueError("Arithmetic comparison of addresses in different sections is not defined ({!r} vs {!r})".format(self, other))
        return self.offset > other.offset

    def __eq__(self, other):
        if not isinstance(other, Addr):
            return NotImplemented
        if self.section != other.section:
            raise ValueError("Arithmetic comparison of addresses in different sections is not defined ({!r} vs {!r})".format(self, other))
        return self.offset == other.offset

    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    def __ge__(self, other):
        return self.__gt__(other) or self.__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        if self.section:
            return hash(self.section.name) + self.offset
        else:
            return self.offset


class Symbol (Addr):
    def __init__(self, section, offset, name):
        Addr.__init__(self, section, offset, name)
        self.is_global = False
        self.type = None


class RegisterValue:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        value = self.value
        if isinstance(value, int):
            return "0x{:08x}".format(value & 0xffffffff)
        else:
            return str(self.value)

    def __add__(self, other):
        if other is None:
            return None
        if isinstance(other, RegisterValue) and isinstance(other.value, int):
            other = other.value
        if isinstance(other, int):
            if other == 0:
                return self
            elif isinstance(self.value, (int, Addr)):
                return RegisterValue(self.value + other)
            else:
                return OffsetRegisterValue(self, other)
        elif isinstance(self.value, int):
            return other.__add__(self.value)
        else:
            debug(2, "Note: Attempt to add incompatible register values ({} + {}). Returning None.".format(self, other))
            return None

    __radd__ = __add__

    def __sub__(self, other):
        if other is None:
            return None
        if isinstance(other, RegisterValue) and isinstance(other.value, int):
            other = other.value
        if isinstance(other, int):
            return self.__add__(-other)
        else:
            debug(2, "Note: Attempt to subtract incompatible register values ({} - {}). Returning None.".format(self, other))
            return None

    def get_addr(self):
        if isinstance(self.value, Addr):
            return self.value
        return None

    def __eq__(self, other):
        # Basically, if two of these are the same, they should produce the same
        # string output (since that's really what we care about anyway), so
        # it's easiest just to use that to determine whether they're 'equal' or
        # not.
        return str(self) == str(other)

    def __ne__(self, other):
        return not self.__eq__(other)


class OffsetRegisterValue (RegisterValue):
    def __init__(self, other, offset):
        RegisterValue.__init__(self, None)
        self.other = other
        self.offset = offset

    def __str__(self):
        if self.offset >= 0:
            return "{}+0x{:x}".format(self.other, self.offset)
        else:
            return "{}-0x{:x}".format(self.other, -self.offset)

    def __add__(self, other):
        if isinstance(other, RegisterValue) and isinstance(other.value, int):
            other = other.value
        if isinstance(other, int):
            new_offset = self.offset + other
            if new_offset:
                return OffsetRegisterValue(self.other, new_offset)
            else:
                return self.other
        else:
            debug(2, "Note: Attempt to add incompatible register values ({} + {}). Returning None.".format(self, other))
            return None

    __radd__ = __add__

    def get_addr(self):
        addr = self.other.get_addr()
        if not addr:
            return None
        return addr + self.offset


class IndirectRegisterValue (RegisterValue):
    def __init__(self, ref):
        RegisterValue.__init__(self, None)
        self.ref = ref

    def __str__(self):
        return "[{}]".format(self.ref)

    def get_addr(self):
        return None


class StoreOpNote:
    "Used for the opcode note for 'store' opcodes.  Holds two values and formats them into the appropriate format when rendering output."
    def __init__(self, v1, v2, width):
        self.v1 = v1
        self.v2 = v2
        self.width = width

    def __str__(self):
        if self.v1 is None:
            v1text = '?'
        elif not isinstance(self.v1, RegisterValue):
            v1text = str(self.v1)
        elif isinstance(self.v1.value, int):
            v1 = self.v1.value
            mask = (1 << (self.width * 8)) - 1
            v1text = '0x{:0{digits}x}'.format(v1 & mask, digits=self.width*2)
        else:
            v1text = str(self.v1)
        return "{} -> {}".format(v1text, self.v2)


class Region:
    region_type = "invalid"

    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.section = start.section

    def code_analysis(self):
        return False

    def adjust_end(self, end):
        self.end = end

    def rewrite(self, rewrite_opts):
        pass

    def dump(self, writer):
        # We shouldn't ever get here, because nobody should be creating a
        # direct instance of Region, and all subclasses should be overriding
        # the 'dump' method.
        if self.start != self.end:
            log.warning("Region.dump called directly (this shouldn't happen).  {!r} - {!r} ({} bytes) will not be represented in output.".format(self.start, self.end, self.end - self.start))
            writer.warning("{} bytes skipped".format(self.end - self.start))

    def get_callmap(self):
        return None

    def __repr__(self):
        return "<{} region at {!r}>".format(self.region_type, self.start.loc_str())


class FunctionRegion (Region):
    region_type = "function"

    def __init__(self, start, end=None, func_name=None):
        Region.__init__(self, start, end)
        self.func_name = func_name
        self.disassembly = None
        self.call_targets = []
        self.stack = StackPseudoSection(self)

    def code_analysis(self):
        if self.disassembly is not None:
            # We've already done our bit.
            return False
        debug(1, "Starting analysis of code at {!r}...".format(self.start))

        # First, get the raw disassembly, perform any relocation fixups, figure
        # out where all the branches go to, and make sure we have the right end
        # point of the routine.
        disassembly, branch_dests = self._get_disassembly(self.start, self.end)

        # Check for problems in the resulting disassembly which we might be
        # able to fix up with another (more informed) run
        if self._check_disassembly(disassembly, branch_dests):
            debug(2, "Re-running disassembly based on new information...")
            disassembly, branch_dests = self._get_disassembly(self.start, self.end)

        if disassembly:
            # Next, go through and try to determine the values of the registers at
            # each point.
            self._resolve_regs(disassembly, branch_dests)

            # And finally, make annotations all over the place based on the results.
            self._perform_annotations(disassembly)

            self.end = disassembly[-1].addr + disassembly[-1].length
        else:
            self.end = self.start
        self.disassembly = disassembly
        self.cleanup()
        return True

    def _get_disassembly(self, start, end):
        debug(2, "Performing relocations...")
        section = self.section
        disassembly = []
        branch_dests = {}
        generator = section.objfile.disassemble(start, end)
        no_trim_func = 'no-trim-func' in section.annotations.get(start, {})
        opcode_marker = section.find_next_annotation(start, 'opcode') or end
        while True:
            try:
                opcode = next(generator)
            except StopIteration:
                break
            if opcode.addr == opcode_marker:
                debug(3, "Opcode at {!r} matches 'opcode' annotation at {!r}.  No resynchronization required.".format(opcode.addr, opcode_marker))
                opcode_marker = section.find_next_annotation(opcode_marker, 'opcode') or end
            elif opcode.addr + opcode.length > opcode_marker:
                debug(2, "Opcode at {!r} overlaps 'opcode' annotation at {!r}.  Resynchronizing disassembly.".format(opcode.addr, opcode_marker))
                if section.data[opcode.addr.offset] == 0 and section.data[opcode_marker.offset - 1] == 0:
                    # looks to be padding (zeros).  Use '.skip' opcode to
                    # indicate this.
                    skip = opcode_marker.offset - opcode.addr.offset
                    disassembly.append(Opcode(opcode.addr, skip, '.skip', [str(skip)]))
                else:
                    for i in range(opcode.addr.offset, opcode_marker.offset):
                        disassembly.append(Opcode(Addr(section, i), 1, '.byte', ['0x{:02x}'.format(section.data[i])]))
                flush(generator)
                generator = section.objfile.disassemble(opcode_marker, end)
                opcode_marker = section.find_next_annotation(opcode_marker, 'opcode') or end
                continue
            instr = opcode.instr
            if instr.endswith('.n'):
                instr = instr[:-2]
            opcode_info = OPCODE_INFO.get(instr, {})
            opcode_type = opcode_info.get('type')
            slot0_arg = opcode_info.get('slot0')
            if slot0_arg is not None:
                if opcode.addr in section.slot_relocs:
                    slot, sym, addend = section.slot_relocs[opcode.addr]
                    old_argstr = opcode.argstr()
                    addr = sym + addend
                    # We only ever have SLOT0 fixups on Xtensa, so just
                    # replace the first non-register arg.
                    opcode.args[slot0_arg] = addr
                    debug(3, "Applied SLOT0 relocation at {!r}.  Old opcode: '{} {}' New opcode: '{} {}'".format(opcode.addr, opcode.instr, old_argstr, opcode.instr, opcode.argstr()))
                else:
                    # If slot0 wasn't updated with a relocation, try to
                    # determine what type of value it should be.
                    if opcode_type in ('branch', 'call', 'literal'):
                        # If it's a branch/call/l32r instruction, the arg is a
                        # label, which the disassembler writes as just the
                        # address (base 16), so convert it to an Addr in the
                        # same section with that offset.
                        value = int(opcode.args[slot0_arg], 16)
                        if value > 0x7fffffff:
                            value -= 0x100000000
                        addr = Addr(section, value)
                        opcode.args[slot0_arg] = addr
                    else:
                        # If it's not a branch/call/l32r, and wasn't relocated,
                        # assume it's just an integer instead of an address
                        value = int(opcode.args[slot0_arg], 0)
                        if value > 0x7fffffff:
                            value -= 0x100000000
                        opcode.args[slot0_arg] = value
                if opcode_type == 'branch':
                    opcode.dest_addr = addr
                    branch_dests[addr] = None
            elif opcode.addr in section.slot_relocs:
                log.warning("SLOT0 relocation specified for {} instruction ({!r}).  Do not know how to do this (relocation not applied).".format(opcode.instr, opcode.addr))
            if opcode_type == 'call':
                addr = opcode.args[0]
                if isinstance(addr, Addr):
                    opcode.dest_addr = addr
            disassembly.append(opcode)
            if opcode_info.get('flow_break'):
                # We encountered either a return or unconditional jump
                # instruction.  If we didn't previously see any jumps/branches
                # to a point later than this in the code, then it shouldn't
                # ever be possible for code flow to go past this point, which
                # means we're at the end of the function.
                if not no_trim_func:
                    if not branch_dests or opcode.addr >= max(branch_dests.keys()):
                        break
                next_addr = opcode.addr + opcode.length
                if next_addr not in branch_dests:
                    if (next_addr + 1) in branch_dests:
                        # If it's one byte off, there's no way that byte could
                        # reasonably be anything other than padding..
                        debug(2, "{!r}: Padding detected after jump/ret (1 byte).  Resyncing disassembly at next branch target ({!r}).".format(next_addr, next_addr + 1))
                        disassembly.append(Opcode(next_addr, 1, '.skip', ['1']))
                        flush(generator)
                        generator = section.objfile.disassemble(next_addr + 1, end)
                    elif (next_addr + 2) in branch_dests:
                        if self.section.data[next_addr.offset:next_addr.offset+2] == b'\0\0':
                            debug(2, "{!r}: Padding detected after jump/ret (2 bytes).  Resyncing disassembly at next branch target ({!r}).".format(next_addr, next_addr + 2))
                            disassembly.append(Opcode(next_addr, 2, '.skip', ['2']))
                            flush(generator)
                            generator = section.objfile.disassemble(next_addr + 2, end)
                        else:
                            # If the intervening bytes are not zero,
                            # technically this still could be some sort of
                            # padding, but it also might be a valid opcode
                            # (which is referenced by a branch later on which
                            # we haven't encountered yet).  Take the safest
                            # guess and assume it's not just padding.
                            debug(2, "{!r}: Next branch target after jump is 2 bytes ahead, but intervening bytes are not zero.  Continuing on as-is and hoping for the best.".format(next_addr))
                    else:
                        debug(2, "{!r}: No branch target found immediately after jump/ret.  Continuing on and hoping for the best.".format(next_addr))

        # Go back through and fill in our branch table with the actual opcode
        # indexes.
        for i in range(len(disassembly)):
            addr = disassembly[i].addr
            if addr in branch_dests:
                branch_dests[addr] = i

        return (disassembly, branch_dests)

    def _check_disassembly(self, disassembly, branch_dests):
        changed = False

        # Find misaligned branch dests
        dests = sorted(branch_dests.keys())
        for opcode in disassembly:
            while dests and opcode.addr >= dests[0]:
                dests.pop(0)
            if not dests:
                break
            if opcode.addr + opcode.length > dests[0]:
                debug(3, "Found misaligned branch target at {!r}.  Annotating as opcode.".format(dests[0]))
                self.section.annotate(dests[0], 'opcode', True)
                changed = True
        return changed

    def _resolve_regs(self, disassembly, branch_dests):
        # This is the real core of the static code analysis.  We go through
        # step by step and try to determine what each register holds at each
        # point, and save that information in the opcode.  For portions of code
        # which can be reached multiple ways, however, we need to make sure we
        # only record a register value if it's always going to be the same
        # regardless of how the code was reached.  We do this by propagating
        # register values both forward to the next opcode and to any
        # branch/jump destinations, and making sure we resolve any conflicts by
        # only keeping values which agree in all cases.
        #
        # This process will also make sure that the following attributes on
        # each opcode are set if appropriate:
        #   value = The calculated expression value associated with the opcode.
        #       (For add/sub/etc this is the calculated value which ends up
        #       being stored in the register.  For load/move/store/etc this is
        #       the literal or memory-location-reference involved.  For 'ret',
        #       it's the value of the a2 register, and so on.)
        #   dest_addr = The destination address for call/jump/branch instrs.
        #
        # Because propagating to branch dests could update registers for an
        # opcode we've already processed, we need to perform multiple passes
        # until we get to a point where nothing's changing anymore (this is
        # safe because we only ever modify an opcode's regs by removing
        # entries, never adding, so it isn't possible to get into an endless
        # loop this way).
        debug(2, "Resolving regs...")
        #TODO: abi/noabi
        # On entry into a function, all we really know is that a1 points to the
        # top of our local stack (frame pointer), and that a2 through a7 are
        # arguments passed from the caller.
        regs = {'a1': RegisterValue(Addr(self.stack, 0))}
        for i in range(2, 8):
            regs['a{}'.format(i)] = RegisterValue('arg{}'.format(i - 2))
        disassembly[0].regs = regs
        repeat_pass = True
        while repeat_pass:
            repeat_pass = False
            i = 0
            while i < len(disassembly):
                opcode = disassembly[i]
                if opcode.regs_resolved:
                    i += 1
                    continue
                if opcode.regs is None:
                    i += 1
                    continue
                repeat_pass = True
                if i + 1 < len(disassembly):
                    next_opcode = disassembly[i + 1]
                else:
                    next_opcode = None

                debug_regs(3, "{!r}: ".format(opcode.addr), opcode.regs)
                debug(3, "    {} {}".format(opcode.instr, opcode.argstr()))
                instr = opcode.instr
                if instr.endswith('.n'):
                    instr = instr[:-2]
                opcode_info = OPCODE_INFO.get(instr, {})
                opcode_type = opcode_info.get('type')
                regs = opcode.regs.copy()
                value = None
                if opcode_type == 'literal':
                    try:
                        addr = opcode.args[1]
                        if addr.section:
                            value = RegisterValue(addr.section.get_word(addr))
                    except IndexError:
                        pass
                elif opcode_type in ('load', 'store'):
                    value = regs.get(opcode.args[1])
                    if value:
                        value = IndirectRegisterValue(value + int(opcode.args[2], 0))
                elif opcode_type == 'move':
                    value = opcode.args[1]
                    if isinstance(value, str):
                        value = regs.get(value)
                    else:
                        value = RegisterValue(value)
                elif instr == 'or' and opcode.args[1] == opcode.args[2]:
                    # This is effectively the same as a mov
                    value = regs.get(opcode.args[1])
                elif instr in ('addi', 'addmi'):
                    value = regs.get(opcode.args[1])
                    if value:
                        value += opcode.args[2]
                elif instr == 'add':
                    value1 = regs.get(opcode.args[1])
                    value2 = regs.get(opcode.args[2])
                    if value1 and value2:
                        value = value1 + value2
                elif instr == 'sub':
                    value1 = regs.get(opcode.args[1])
                    value2 = regs.get(opcode.args[2])
                    if value1 and value2:
                        value = value1 - value2
                elif instr == 'ret':
                    value = regs.get('a2') #TODO: abi/noabi
                opcode.value = value
                if opcode_info.get('value_to_reg', True):
                    # For most opcodes, whatever we determined the 'value'
                    # value to be is also what will be stored in the register named
                    # in the first argument, so update that register with the same
                    # value.
                    r = opcode.args[0]
                    if isinstance(r, str):
                        regs[r] = value
                # For a few opcodes, they can potentially change a bunch of
                # registers, so we need to make sure we forget any values which
                # might potentially have been modified by them.
                #TODO: abi/noabi and calls
                for r in opcode_info.get('clobber_regs', ()):
                    if r in regs:
                        regs[r] = None

                opcode.regs_resolved = True

                if opcode_type == 'call':
                    addr = opcode.args[0]
                    if isinstance(addr, str):
                        addr = opcode.regs.get(addr)
                        if addr:
                            opcode.value = addr
                            addr = addr.get_addr()
                            opcode.dest_addr = addr

                # If this is a branch/jump, write the new regs to the branch
                # destination.
                dest_i = None
                if opcode_type == 'branch':
                    if 'slot0' in opcode_info:
                        addr = opcode.args[opcode_info['slot0']]
                    else:
                        # If there's no slot0, then arg 0 must be a register
                        # name..
                        addr = regs.get(opcode.args[0])
                    if addr is not None:
                        opcode.dest_addr = addr
                        dest_i = branch_dests[addr]
                        if dest_i is not None:
                            dest_opcode = disassembly[dest_i]
                            self._update_opcode_regs(dest_opcode, regs, opcode.addr)
                        else:
                            debug(1, "Opcode at {!r} branches to {!r}, but that does not correspond to an opcode in this code block.  Cannot propagate register values.".format(opcode.addr, addr))

                if opcode_info.get('flow_break'):
                    # There's no way to 'fall through' from this opcode to
                    # the next one, so take the branch if there's something
                    # to do there (if it jumps to somewhere that's already
                    # fully resolved, just consider this the end of flow
                    # and break out of the loop).
                    if dest_i is not None and not dest_opcode.regs_resolved:
                        debug(3, "Following unconditional jump to {!r}...".format(dest_opcode.addr))
                        i = dest_i - 1
                    else:
                        debug(3, "Reached end of code path.")
                        break
                elif next_opcode:
                    # Write the new regs to the next opcode in sequence
                    self._update_opcode_regs(next_opcode, regs, opcode.addr)

                i += 1
            if repeat_pass:
                debug(3, "Changes may have been made to some regs.  Performing another pass...")


    def _update_opcode_regs(self, opcode, regs, from_addr):
        "Apply the current set of regs to the opcode, making sure that if it already has regs defined we only keep those values which match in both cases.  Returns True if changes were made or False if not."

        if opcode.regs is None:
            opcode.regs = regs.copy()
            opcode.regs_resolved = False
            changed = True
        else:
            new_regs = {}
            changed = False
            for k, v in opcode.regs.items():
                if regs.get(k) == v:
                    new_regs[k] = v
                else:
                    changed = True
            if changed:
                debug(3, "Propagating regs from {!r} to {!r} changed destination regs.".format(from_addr, opcode.addr))
                debug_regs(3, "- Old: ", opcode.regs)
                debug_regs(3, "- Applied: ", regs)
                debug_regs(3, "- New: ", new_regs)
                opcode.regs = new_regs
                opcode.regs_resolved = False
        return changed

    def _perform_annotations(self, disassembly):
        # This phase goes through each opcode and:
        # * Adds opcode-notes as appropriate based on the register values/etc
        #   to try to give the reader some helpful info on what data values
        #   each instruction is working with.
        # * Makes annotations elsewhere in the code based on what the opcode is
        #   doing (noting call destinations as entry points, noting data access
        #   locations and access-size info, etc)

        debug(2, "Annotating...")
        for opcode in disassembly:
            instr = opcode.instr
            if instr.endswith('.n'):
                instr = instr[:-2]
            opcode_info = OPCODE_INFO.get(instr, {})
            opcode_type = opcode_info.get('type')

            if opcode.value:
                if opcode_type == 'store':
                    v = (opcode.regs or {}).get(opcode.args[0])
                    if v is None:
                        v = opcode.args[0]
                    opcode.add_note(StoreOpNote(v, opcode.value, OPCODE_ACCESS_WIDTH[instr]))
                else:
                    opcode.add_note(opcode.value)

            if instr == 'l32r':
                debug(3, "{!r}: annotating {!r} as literal data.".format(opcode.addr, opcode.args[1]))
                addr = opcode.args[1]
                if addr.section:
                    addr.section.register_literal(addr)
                    addr.section.annotate(addr, 'referenced_by', (opcode.addr, 'load'))
            elif opcode_type in ('load', 'store'):
                if opcode.value:
                    addr = opcode.value.ref.get_addr()
                    if addr and addr.section:
                        debug(3, "{!r}: annotating {!r} as data with {} access size.".format(opcode.addr, addr, OPCODE_ACCESS_WIDTH[instr]))
                        addr.section.register_data(addr, OPCODE_ACCESS_WIDTH[instr])
                        addr.section.annotate(addr, 'referenced_by', (opcode.addr, opcode_type))
                    else:
                        debug(3, "{!r}: data reference location ({!r}) not local.  Not annotating.".format(opcode.addr, addr))
            elif opcode_type == 'call':
                addr = opcode.dest_addr
                if addr:
                    if addr.section:
                        debug(3, "{!r}: annotating {!r} as function entry point.".format(opcode.addr, addr))
                        addr.section.register_entry_point(addr, called_from=opcode.addr)
                    else:
                        debug(3, "{!r}: call destination ({!r}) not local.  Not annotating.".format(opcode.addr, addr))
                    self.call_targets.append((opcode.addr, addr))
                else:
                    debug(3, "{!r}: call destination ({}) value unknown.  No action taken.".format(opcode.addr, opcode.args[0]))
            elif opcode_type == 'branch' and opcode.dest_addr is not None:
                debug(3, "{!r}: annotating {!r} as branch destination.".format(opcode.addr, opcode.dest_addr))
                self.section.register_branch(opcode.addr, opcode.dest_addr)

            # If we haven't already assigned other notes to this opcode, see if
            # we can come up with some useful comments about what's going on
            # based on common code patterns/ABI/etc.
            if not opcode.notes:
                if instr == 'j':
                    if opcode.dest_addr == opcode.addr:
                        opcode.add_note('(halt)')

    def adjust_end(self, end):
        self.end = end
        self.cleanup()

    def cleanup(self):
        old_len = len(self.disassembly)
        while self.disassembly and self.disassembly[-1].addr >= self.end:
            self.disassembly.pop()
        if self.disassembly and self.disassembly[-1].addr + self.disassembly[-1].length > self.end:
            self.disassembly.pop()
        while self.disassembly and self.disassembly[-1].instr in OPCODES_ILLEGAL:
            self.disassembly.pop()
        new_len = len(self.disassembly)
        if new_len != old_len:
            debug(1, "Truncated disassembly for routine at {!r} from {} to {} opcodes".format(self.start, old_len, new_len))
        if self.disassembly:
            self.end = self.disassembly[-1].addr + self.disassembly[-1].length
        else:
            self.end = self.start

        counter = 0
        prev_addr = None
        for addr, note in self.stack.annotations.items():
            if prev_addr:
                self.stack.annotate(prev_addr, 'length', addr - prev_addr)
            self.stack.add_label(addr, '(local{})'.format(counter))
            counter += 1
            prev_addr = addr
        self.stack.add_label(Addr(self.stack, 0), '(top of frame)')
        if prev_addr:
            self.stack.annotate(prev_addr, 'length', -prev_addr.offset)

    def rewrite(self, rewrite_opts):
        if rewrite_opts.get('remove_dotn'):
            for opcode in self.disassembly:
                if opcode.instr.endswith('.n'):
                    debug(2, "Rewrite: {!r}: changing {!r} to {!r}".format(opcode.addr, opcode.instr, opcode.instr[:-2]))
                    opcode.instr = opcode.instr[:-2]
        if rewrite_opts.get('remove_padding'):
            disassembly = []
            for opcode in self.disassembly:
                if opcode.instr == '.skip':
                    if disassembly:
                        disassembly[-1].length += opcode.length
                else:
                    disassembly.append(opcode)
            self.disassembly = disassembly
        if rewrite_opts.get('sr_as_arg'):
            for opcode in self.disassembly:
                instr = opcode.instr.split('.')
                if instr[0] in ('rsr', 'wsr', 'xsr'):
                    old_instr = opcode.tostr()
                    opcode.instr = instr[0]
                    opcode.args.append(instr[1])
                    debug(2, "Rewrite: {!r}: changing {!r} to {!r}".format(opcode.addr, old_instr, opcode.tostr()))
        if rewrite_opts.get('a1_as_sp'):
            for opcode in self.disassembly:
                for i in range(len(opcode.args)):
                    debug(2, "Rewrite: {!r}: changing a1 to sp".format(opcode.addr))
                    if opcode.args[i] == 'a1':
                        opcode.args[i] = 'sp'
        if rewrite_opts.get('or_as_mov'):
            for opcode in self.disassembly:
                if opcode.instr == 'or' and opcode.args[1] == opcode.args[2]:
                    # There is technically no (non-narrow) "mov r1, r2"
                    # instruction in Xtensa.  Instead, this construct in the
                    # source is actually assembled down as an "or r1, r2, r2"
                    # instruction (which has the same effect).  Rewrite this
                    # back to a "mov" for clarity.
                    opcode.instr = 'mov'
                    del opcode.args[2]
        if rewrite_opts.get('inline_literals'):
            i = 0
            while i < len(self.disassembly):
                opcode = self.disassembly[i]
                if opcode.instr == 'l32r':
                    if opcode.value is None:
                        i += 1
                        continue
                    # We're going to be converting this to an inline literal,
                    # which means it won't refer to the l32r target anymore.
                    # Make sure we update the annotation on the target to
                    # reflect this.
                    ref = opcode.args[1]
                    self.section.remove_annotation(ref, 'referenced_by', (opcode.addr, 'load'))
                    try:
                        next_opcode = self.disassembly[i + 1]
                    except IndexError:
                        next_opcode = opcode
                    if opcode.args[0] == 'a0' and next_opcode.instr == 'callx0' and next_opcode.args[0] == 'a0':
                        # 'l32r a0, <ref>' followed by 'callx0 a0' is a common
                        # idiom, and is directly replaceable with a single
                        # 'call0 <dest>' instead
                        del self.disassembly[i]
                        next_opcode.addr = opcode.addr
                        next_opcode.length += opcode.length
                        next_opcode.instr = 'call0'
                        next_opcode.args = [next_opcode.value]
                        next_opcode.notes = []
                        i -= 1
                        debug(2, "Rewrite: {!r}: changing 'l32r'+'callx0' to 'call0'".format(opcode.addr))
                        continue
                    opcode.instr = 'movi'
                    opcode.args[1] = opcode.value
                    if opcode.notes == [str(opcode.value)]:
                        opcode.notes = []
                    debug(2, "Rewrite: {!r}: changing 'l32r' to 'movi'".format(opcode.addr))
                i += 1

    def dump(self, writer):
        writer.spacer_line()
        writer.start_function(self.start)
        if len(self.stack.annotations) > 1:
            writer.comment('Local variables/stack:')
            for addr, note in self.stack.annotations.items():
                # Don't print the entry for offset==0, because that's always
                # just our "(top of frame)" label.
                if addr.offset:
                    label = list(note['label'])[0] + ':'
                    size = list(note.get('data_size', {-1}))[0]
                    length = list(note.get('length', {size}))[0]
                    size_name = SIZE_NAMES.get(size, '???')
                    count = int(length / size)
                    if count > 1:
                        size_name = '{}[{}]'.format(size_name, count)
                    writer.comment('    {:10} {:9} @ -0x{:x}'.format(label, size_name, -addr.offset))
        for opcode in self.disassembly:
            writer.opcode(opcode)
        writer.spacer_line()

    def get_callmap(self):
        return self.call_targets


class DataRegion (Region):
    region_type = "data"


class LiteralPositionRegion (DataRegion):
    region_type = "literal-position"

    def __init__(self, start, end=None):
        if end is None:
            end = start + 4
        Region.__init__(self, start, end)

    def dump(self, writer):
        size = self.end - self.start
        writer.asm_line(self.start, size, '.literal_position', '', check_addr=False)


class BytesDataRegion (DataRegion):
    region_type = "byte-data"

    def __init__(self, start, end=None):
        if end is None:
            end = start + 1
        Region.__init__(self, start, end)
        self.values = start.section.data[start.offset:end.offset]
        self.value = self.values[0]
        self.zero = is_zeroes(self.values)

    def text(self, start=0, size=None):
        if size is None:
            end = len(self.values)
        else:
            end = start + size
        return ', '.join('0x{:02x}'.format(v) for v in self.values[start:end])

    def dump(self, writer):
        size = self.end - self.start
        if size > 4 and self.zero:
            writer.asm_line(self.start, size, '.space', str(size), output_hexdump=False)
        else:
            for i in range(0, len(self.values), 8):
                size = min(8, len(self.values) - i)
                writer.asm_line(self.start + i, size, '.byte', self.text(i, size), output_hexdump=False)


class AsciiDataRegion (DataRegion):
    region_type = "ascii-data"

    def __init__(self, start, end):
        Region.__init__(self, start, end)
        self.values = start.section.data[start.offset:end.offset]
        self.value = str(self.values, 'ascii')
        self.asciiz = self.values[-1] == 0

    def dump(self, writer):
        size = self.end - self.start
        if self.asciiz:
            writer.asm_line(self.start, size, '.asciz', as_string_literal(self.value.rstrip('\x00')))
        else:
            writer.asm_line(self.start, size, '.ascii', as_string_literal(self.value))


class HalfWordDataRegion (DataRegion):
    region_type = "hword-data"

    def __init__(self, start):
        Region.__init__(self, start, start+2)
        self.value = start.section.get_data_hword(start)

    def text(self):
        return '0x{:04x}'.format(self.value)

    def dump(self, writer):
        writer.asm_line(self.start, 2, '.hword', self.text())


class WordDataRegion (DataRegion):
    region_type = "word-data"

    def __init__(self, start):
        Region.__init__(self, start, start+4)
        self.value = start.section.get_data_word(start)

    def text(self):
        return '0x{:08x}'.format(self.value)

    def dump(self, writer):
        writer.asm_line(self.start, 4, '.word', self.text())


class RelocPtrRegion (WordDataRegion):
    region_type = "reloc-ptr"

    def __init__(self, start, sym, addend):
        WordDataRegion.__init__(self, start)
        self.sym = sym
        self.offset = self.value + addend
        self.target_addr = sym + self.offset

    @classmethod
    def promote(cls, obj, sym, addend):
        obj.__class__ = cls
        obj.sym = sym
        obj.offset = obj.value + addend
        obj.target_addr = sym + obj.offset

    def get_word(self, addr):
        if addr == self.start:
            return self.target_addr
        raise ValueError("Attempt to get word from unaligned reference to relocation word ({!r}).  Result is undefined.".format(addr))

    def text(self):
        if self.offset:
            # If we're a pointer of the form <symbol>+<offset>, check to see
            # if the symbol is a section name, and if so whether there's a
            # label associated with that offset in that section, and if so
            # use the name of the label.
            section = self.target_addr.section
            if section and section.name == self.sym.name:
                labels = section.get_labels(self.target_addr.offset)
                if labels:
                    return sorted(labels)[0]
            # If no label, just return the <symbol>+<offset> form.
            return "{}+0x{:x}".format(self.sym, self.offset)
        else:
            return self.sym.name

    def dump(self, writer):
        hexdata = ''.join('{:02x}'.format(b) for b in self.section.data[self.start:self.start+4])
        writer.asm_line(self.start, 4, '.word', self.text())


class PaddingRegion (Region):
    region_type = "padding"

    def dump(self, writer):
        writer.spacer_line()
        writer.comment("NOTE: {} non-alignment zero bytes skipped.".format(self.end - self.start))


class UnknownRegion (Region):
    region_type = "unknown-data"
    space_separate = True

    def dump(self, writer):
        writer.spacer_line()
        writer.comment("NOTE: The following is apparently unreferenced code/data")
        addr = self.start
        while (addr.offset % 4) != 0:
            b = self.section.data[addr]
            writer.asm_line(addr, 1, '.byte', '0x{:02x}'.format(b))
            addr += 1
        while addr <= self.end - 4:
            w = self.section.get_data_word(addr)
            writer.asm_line(addr, 4, '.word', '0x{:08x}'.format(w))
            addr += 4
        while addr < self.end:
            b = self.section.data[addr]
            writer.asm_line(addr, 1, '.byte', '0x{:02x}'.format(b))
            addr += 1
        writer.spacer_line()


class DataEndRegion (Region):
    region_type = "end-of-data"

    def __init__(self, start):
        Region.__init__(self, start, start)

    def dump(self, writer):
        # This isn't a real region type, so don't produce any output.
        pass


class Section:
    sh_type = None
    sh_entsize = 0
    flag_alloc = False
    flag_writable = False
    flag_exec = False
    flag_mergeable = False
    flag_strings = False
    flag_group = False
    flag_tls = False
    process_relocs = True

    def __init__(self, objfile, index, name, data):
        self.objfile = objfile
        self.index = index
        self.name = name
        self.data = data
        self.base_address = None
        self.labels = {}
        self.regions = SortedDict()
        self.slot_relocs = {}
        self.annotations = SortedDict()

    def flags_str(self):
        f = (f[1] for a, f in SECTION_FLAG_ATTRS.items() if getattr(self, a))
        return ''.join(sorted(f))

    def annotate(self, addr, note_type, note_value):
        if addr.offset > len(self.data):
            debug(1, "Note: Attempt to annotate {!r}, which is beyond the end of the section. ({}={})  Ignored.".format(addr, note_type, note_value))
            return
        self.annotations.setdefault(addr, {}).setdefault(note_type, set()).add(note_value)

    def remove_annotation(self, addr, note_type, note_value):
        try:
            self.annotations[addr].get(note_type, set()).remove(note_value)
            debug(3, "Removed annotation {!r} = {!r} at {!r}".format(note_type, note_value, addr))
        except KeyError:
            debug(3, "Attempt to remove annotation {!r} = {!r} at {!r}: No such annotation".format(note_type, note_value, addr))
            debug(3, "Current annotations: {}".format(self.annotations.get(addr)))
            return False
        return True

    def addr_ref(self, addr):
        return "{}+0x{:x}".format(self.name, addr)

    def register_entry_point(self, addr, name=None, called_from=None):
        if not isinstance(addr, Addr) or addr.section is None:
            addr = Addr(self, int(addr))
        elif addr.section != self:
            raise ValueError("Attempt to register entry point {!r} in section {}".format(addr, self.name))
        self.annotate(addr, 'type', 'code')
        self.annotate(addr, 'end-of-code', True)
        self.annotate(addr, 'ref', 'entry_point')
        if name:
            self.annotate(addr, 'name', name)
        if called_from:
            self.annotate(addr, 'ref', 'call')
            self.annotate(addr, 'called_from', called_from)

    def register_literal(self, addr):
        if not isinstance(addr, Addr) or addr.section is None:
            addr = Addr(self, int(addr))
        elif addr.section != self:
            raise ValueError("Attempt to register literal {!r} in section {}".format(addr, self.name))
        self.annotate(addr, 'type', 'data')
        self.annotate(addr, 'ref', 'literal')
        self.annotate(addr, 'data_size', 4)

    def register_data(self, addr, data_size, add_ref=True):
        if not isinstance(addr, Addr) or addr.section is None:
            addr = Addr(self, int(addr))
        elif addr.section != self:
            raise ValueError("Attempt to register data {!r} in section {}".format(addr, self.name))
        addr.section.annotate(addr, 'type', 'data')
        if add_ref:
            addr.section.annotate(addr, 'ref', 'data')
        addr.section.annotate(addr, 'data_size', data_size)

    def register_reloc_ptr(self, addr, sym, addend):
        if not isinstance(addr, Addr) or addr.section is None:
            addr = Addr(self, int(addr))
        elif addr.section != self:
            raise ValueError("Attempt to register relocation {!r} in section {}".format(addr, self.name))
        self.annotate(addr, 'type', 'data')
        self.annotate(addr, 'ref', 'reloc')
        region = RelocPtrRegion(addr, sym, addend)
        self.add_region(region)
        if region.target_addr and region.target_addr.section:
            region.target_addr.section.annotate(region.target_addr, 'ref', 'reloc_target')
            region.target_addr.section.annotate(region.target_addr, 'referenced_by', (addr, 'reloc'))
        return region

    def register_branch(self, from_addr, to_addr):
        if not isinstance(from_addr, Addr) or from_addr.section is None:
            from_addr = Addr(self, int(from_addr))
        if not isinstance(to_addr, Addr) or to_addr.section is None:
            to_addr = Addr(self, int(to_addr))
        if from_addr.section != self or to_addr.section != self:
            raise ValueError("Attempt to register branch from {!r} -> {!r} in section {}".format(from_addr, to_addr, self.name))
        self.annotate(to_addr, 'type', 'code')
        self.annotate(to_addr, 'ref', 'branch')
        self.annotate(to_addr, 'branch_from', from_addr)

    def add_slot_reloc(self, addr, slot, sym, addend):
        self.slot_relocs[addr] = (slot, sym, addend)

    def get_labels(self, addr):
        if not isinstance(addr, Addr) or addr.section is None:
            addr = Addr(self, int(addr))
        elif addr.section != self:
            raise ValueError("Attempt to get a label for {!r} from section {}".format(addr, self.name))
        return self.annotations.get(addr, {}).get('label')

    def add_label(self, addr, label):
        if not isinstance(addr, Addr) or addr.section is None:
            addr = Addr(self, int(addr))
        elif addr.section != self:
            raise ValueError("Attempt to set a label for {!r} in section {}".format(addr, self.name))
        self.annotate(addr, 'label', label)
        return self.labels.setdefault(addr, label)

    def get_word(self, addr):
        region = self.get_region(addr)
        if hasattr(region, 'get_word'):
            return region.get_word(addr)
        return self.get_data_word(addr)

    def get_data_byte(self, addr):
        return self.data[int(addr)]

    def get_data_hword(self, addr):
        addr = int(addr)
        if addr < 0 or addr > len(self.data) - 2:
            raise IndexError(addr)
        if self.objfile.little_endian:
            return struct.unpack_from('<H', self.data, addr)[0]
        else:
            return struct.unpack_from('>H', self.data, addr)[0]

    def get_data_word(self, addr):
        addr = int(addr)
        if addr < 0 or addr > len(self.data) - 4:
            raise IndexError(addr)
        if self.objfile.little_endian:
            return struct.unpack_from('<I', self.data, addr)[0]
        else:
            return struct.unpack_from('>I', self.data, addr)[0]

    def get_region(self, offset):
        if not self.regions:
            return None
        if isinstance(offset, Addr):
            if offset.section != self:
                return None
            offset = offset.offset
        start = self.regions.iloc[self.regions.bisect(offset) - 1]
        region = self.regions[start]
        if region.start.offset <= offset and region.end.offset > offset:
            return region
        return None

    def del_region(self, region):
        addr = region.start.offset
        if self.regions.get(addr) == region:
            del self.regions[addr]
        else:
            raise ValueError("Region {!r} has not been added to section {!r}".format(region, self.name))

    def add_region(self, region):
        addr = region.start.offset
        if addr in self.regions:
            old_region = self.regions[addr]
            if region.__class__ == old_region.__class__:
                # Same region type as already there.  Ignore this add request.
                return False
            if isinstance(old_region, region.__class__):
                # What's already there is a subclass (more specific type) than
                # what we're trying to add.  Just ignore the new add.
                return False
            if isinstance(region, old_region.__class__):
                # New type is a subclass (more specific type) of what's already
                # there.  Replace the old one with the new more specific one.
                self.regions[addr] = region
                return True
            # If we got here, the two types are entirely conflicting.  Keep the
            # original one, but print a warning.
            log.warn("Conflicting region types for {}+0x{:x} ({} vs {})".format(self.name, addr, old_region.region_type, region.region_type))
            return False
        # Nothing already at that location.  Insert the new one.
        self.regions[addr] = region
        return True

    def code_analysis(self):
        changed = False
        for start in self.find_new_function_regions():
            end = self.find_end_of_code(start)
            if end is None:
                end = Addr(self, len(self.data))
            debug(2, "Found new code region at {!r} - {!r}".format(start, end))
            region = FunctionRegion(start, end)
            changed = self.add_region(region)
        for region in list(self.regions.values()):
            changed = region.code_analysis() or changed
            if region.start == region.end:
                # This generally means a FunctionRegion determined that there
                # isn't actually valid code at that location, so we should
                # remove it (and remove the 'code' annotation so we don't keep
                # trying to add it again).
                debug(2, "Code region at {!r} turned out to be empty.  Removing code annotation from address.".format(region.start))
                self.del_region(region)
                self.remove_annotation(region.start, 'type', 'code')
        return changed

    def find_new_function_regions(self):
        current_end = Addr(self, 0)
        for addr, notes in list(self.annotations.items()):
            debug(3, "find_new_function_regions: next note at {!r}".format(addr))
            if addr < current_end:
                debug(3, "find_new_function_regions: addr ({!r}) less than current_end ({!r}).  Skipping.".format(addr, current_end))
                continue
            if 'code' in notes.get('type', {}):
                debug(3, "find_new_function_regions: type=code")
                region = self.get_region(addr)
                if isinstance(region, FunctionRegion):
                    debug(3, "find_new_function_regions: FunctionRegion from {!r} to {!r} already exists.  Skipping.".format(region.start, region.end))
                    current_end = region.end
                    continue
                debug(3, "find_new_function_regions: returning {!r}".format(addr))
                yield addr
            else:
                debug(3, "find_new_function_regions: type!=code")

    def find_end_of_code(self, start):
        #TODO: is there a more efficient way to do this?
        for addr, notes in self.annotations.items():
            if addr <= start:
                continue
            if 'code' not in notes.get('type', {'code'}):
                return addr
            if 'end-of-code' in notes:
                return addr
        return None

    def find_next_annotation(self, start, notetypes):
        if isinstance(notetypes, str):
            notetypes = {notetypes}
        else:
            notetypes = set(notetypes)
        #TODO: is there a more efficient way to do this?
        for addr, notes in self.annotations.items():
            if addr <= start:
                continue
            if notes.keys() & notetypes:
                return addr
        return None

    def data_analysis(self):
        changed = False
        for addr in self.find_new_data_regions():
            ann = self.annotations[addr]
            data_type = ann.get('data_type', {})
            data_size = ann.get('data_size', {})
            end = None
            if 'str' in data_type:
                dtype = 'str'
                datalen = ann.get('data_length', {})
                if datalen:
                    end = addr + max(datalen)
                else:
                    end = self.find_next_region(addr)
                    strlen = is_ascii_data(addr, end, False)
                    if strlen:
                        end = addr + strlen
                    else:
                        # It's marked as a string, but it's not ASCII, and we
                        # don't know where the end is.  Just represent it as
                        # .bytes instead.
                        debug(1, "{!r} marked as string, but not ASCII.  Representing as .byte data instead.".format(addr))
                        dtype = 'bytes'
            elif 'bytes' in data_type:
                dtype = 'bytes'
                datalen = ann.get('data_length', {})
                if datalen:
                    end = addr + max(datalen)
                else:
                    end = self.find_next_region(addr)
            elif 4 in data_size:
                dtype = 4
            elif 2 in data_size:
                dtype = 2
            elif 1 in data_size:
                dtype = 1
            else:
                # Default to word, but only if we're starting on a 32-bit
                # boundary, and only if there's exactly 4 bytes between us and
                # the next item.  If not, check to see if the data in the
                # region looks like an ASCII or ASCII-Z string.  Otherwise fall
                # back to '.byte'.
                end = self.find_next_region(addr)
                size = end - addr
                if not size:
                    # This could conceivably happen in some cases if there's an
                    # annotation at the beginning of an empty section.
                    continue
                elif size == 4 and not addr.offset % 4:
                    dtype = 4
                else:
                    strlen = is_ascii_data(addr, end)
                    if strlen >= MIN_ASCII_LEN:
                        dtype = 'str'
                        end = addr + strlen
                        self.annotate(addr, 'ref', 'str')
                        self.annotate(addr, 'data_type', 'str')
                    else:
                        dtype = 'bytes'
                        #self.annotate(addr, 'data_type', 'bytes')

            try:
                if dtype == 4:
                    region = WordDataRegion(addr)
                elif dtype == 2:
                    region = HalfWordDataRegion(addr)
                elif dtype == 1:
                    region = BytesDataRegion(addr)
                elif dtype == 'str':
                    region = AsciiDataRegion(addr, end)
                else:
                    region = BytesDataRegion(addr, end)

                debug(1, "Identified {} region at {!r}".format(region.region_type, addr))
                self.add_region(region)
                changed = True
            except IndexError:
                log.warning("Apparent reference to area outside of segment data ({!r} referenced by {}".format(addr, ann.get('referenced_by', '(unknown)')))

        return changed

    def find_new_data_regions(self):
        current_end = Addr(self, 0)
        for addr, ann in list(self.annotations.items()):
            debug(3, "find_new_data_regions: next note at {!r}".format(addr))
            if addr < current_end:
                debug(3, "find_new_data_regions: addr ({!r}) less than current_end ({!r}).  Skipping.".format(addr, current_end))
                continue
            addr_type = ann.get('type', {})
            if not addr_type and 'ref' in ann:
                addr_type = {'data'}
            if 'data' in addr_type:
                debug(3, "find_new_data_regions: type=data")
                region = self.get_region(addr)
                if region:
                    debug(3, "find_new_data_regions: Region from {!r} to {!r} already exists.  Skipping.".format(region.start, region.end))
                    current_end = region.end
                    continue
                debug(3, "find_new_data_regions: returning {!r}".format(addr))
                yield addr
            else:
                debug(3, "find_new_data_regions: type!=data")

    def find_next_region(self, addr):
        try:
            return self.annotations.iloc[self.annotations.bisect(addr)]
        except IndexError:
            return Addr(self, len(self.data))

    def get_max_region_size(self, start):
        end = self.regions.iloc[self.regions.bisect(start.offset)]
        return end - start

    def rewrite(self, rewrite_opts):
        debug(1, "Rewriting section {}".format(self.name))
        for r in self.regions.values():
            r.rewrite(rewrite_opts)
        if rewrite_opts.get('inline_literals'):
            region_addrs = list(self.regions.keys())
            prev_r = None
            for addr in region_addrs:
                r = self.regions[addr]
                if isinstance(r, WordDataRegion):
                    ann = self.annotations.get(r.start, {})
                    if ann.get('type') == {'data'} and 'literal' in ann.get('ref', []):
                        # It's a word literal or reloc target.  Is it
                        # referenced by anything after we've replaced all the
                        # 'l32r's?
                        if ann.get('referenced_by'):
                            debug(2, "Rewrite: {!r}: literal data found, but still has referrers.  Not changing.".format(r.start))
                            continue
                        # As expected, nothing left explicitly referring to
                        # this.  Replace it with a '.literal_position'
                        # directive instead.
                        debug(2, "Rewrite: {!r}: changing data word to .literal_position".format(r.start))
                        # Since there's nothing referencing this, no need for a
                        # label anymore.
                        ann['label'] = set()
                        if isinstance(prev_r, LiteralPositionRegion):
                            debug(3, "Merging {!r} with previous .literal_position".format(r.start))
                            del self.regions[addr]
                            prev_r.end = r.end
                            continue
                        else:
                            self.regions[addr] = LiteralPositionRegion(r.start)
                prev_r = self.regions[addr]

    def cleanup(self):
        debug(1, "Applying cleanups for section {}".format(self.name))
        offset = 0
        for r in self.regions.values():
            start_offset = r.start.offset
            if start_offset > offset:
                self.fill_in_region_gap(offset, start_offset)
            offset = r.end.offset
        if offset != len(self.data):
            self.fill_in_region_gap(offset, len(self.data))
        if self.base_address is not None:
            self.identify_address_literals()

    def fill_in_region_gap(self, start, end):
        debug(2, "Region gap found from 0x{:x} to 0x{:x}...".format(start, end))
        data = self.data
        # If we're not starting on a 32-bit word boundary, check to see if the
        # bytes between here and the next word boundary are zeroes, and if so
        # assume that bit is just alignment padding (and let the DumpWriter
        # code handle it with a '.balign' directive), and shift the start
        # appropriately.
        #TODO: we should base this on the section's specified alignment instead of always assuming 4
        if start % 4 != 0:
            align_to = start + (4 - (start % 4))
            if end >= align_to and is_zeroes(data[start:align_to]):
                debug(2, " - 0x{:x} to 0x{:x} taken as alignment padding.".format(start, align_to))
                start = align_to
        while start < end:
            for i in range(start, end):
                if data[i]:
                    debug(3, " - Found nonzero byte at 0x{:x}".format(i))
                    i -= 1
                    break
            i += 1
            if i != end:
                i -= (i % 4)
            if (i == end) or ((i - start) >= MIN_PADDING_REGION):
                # We found a block of zeroes.  Insert a padding region.
                self.add_region(PaddingRegion(Addr(self, start), Addr(self, i)))
                debug(1, "Added padding region from 0x{:x} to 0x{:x}".format(start, i))
                start = i
            else:
                # We found nonzero data.  We'll need to insert an
                # "unknown-data" region.  First, let's look for the end of the
                # nonzero data.
                for j in range(i, end, 4):
                    try:
                        v = data[j] | data[j+1] | data[j+2] | data[j+3]
                        if v == 0 and is_zeroes(data[j:j+MIN_PADDING_REGION]):
                            # Ok, found a substantial block of zeroes, so we'll
                            # consider this the end of the "unknown-data"
                            # portion.
                            debug(3, " - Found {} zeroes starting at 0x{:x}".format(MIN_PADDING_REGION, j))
                            j -= 4
                            break
                    except IndexError:
                        # We must have run past the end of 'data'. This is OK,
                        # just make the unknown region go to the end.
                        j = end
                        break
                j = min(j + 4, end)
                self.add_region(UnknownRegion(Addr(self, start), Addr(self, j)))
                debug(1, "Added unknown-data region from 0x{:x} to 0x{:x}".format(start, j))
                start = j

    def identify_address_literals(self):
        # When operating on a raw input with a known base address, try to find
        # any literals which have a value corresponding to the address of
        # something noteworthy in the same segment.  If we find any, convert
        # them to address pointers.
        start_offset = self.base_address
        end_offset = start_offset + len(self.data)
        sym = Symbol(self, 0, self.name)
        for r in list(self.regions.values()):
            if not isinstance(r, WordDataRegion):
                continue
            refs = self.annotations.get(r.start, {}).get('ref', {})
            if 'literal' not in refs:
                continue
            if r.value < start_offset or r.value >= end_offset:
                continue
            addr = Addr(self, r.value - start_offset)
            dest_notes = self.annotations.get(addr, {})
            refs = dest_notes.get('ref', {})
            syms = dest_notes.get('symbol', {})
            if (refs and refs != {'branch'}) or syms:
                debug(1, "Literal at {!r} appears to be an address pointer to {!r}.  Converting to address reference.".format(r.start, addr))
                RelocPtrRegion.promote(r, sym, -start_offset)


    def dump(self, writer):
        if not self.regions and not writer.output_empty_sections:
            return
        writer.start_section(self)
        for r in self.regions.values():
            r.dump(writer)
        writer.end_section()

    def get_callmap(self):
        result = {}
        for r in self.regions.values():
            m = r.get_callmap()
            if m is not None:
                result[r] = m
        return result


class CodeSection (Section):
    sh_type = 'SHT_PROGBITS'
    flag_alloc = True
    flag_exec = True


class DataSection (Section):
    sh_type = 'SHT_PROGBITS'
    flag_alloc = True
    flag_writable = True


class BssSection (Section):
    """A BssSection by definition has all its data set to zero, so instead of asking for the section data, we just accept a length and auto-generate an appropriately-sized zero-buffer instead."""
    sh_type = 'SHT_NOBITS'
    flag_alloc = True

    def __init__(self, objfile, index, name, length):
        Section.__init__(self, objfile, index, name, b'\0' * length)


class MetadataSection (Section):
    process_relocs = False

    def code_analysis(self):
        pass

    def data_analysis(self):
        pass

    def cleanup(self):
        pass

    def dump(self, writer):
        pass


class NoteSection (MetadataSection):
    def __init__(self, objfile, index, name, data):
        MetadataSection.__init__(self, objfile, index, name, data)
        self.notes = {}
        i = 0
        while i < len(data) - 12:
            if self.objfile.little_endian:
                name_size, desc_size, note_type = struct.unpack_from('<III', data, i)
            else:
                name_size, desc_size, note_type = struct.unpack_from('<III', data, i)
            i += 12
            try:
                name = data[i:i+name_size]
                i += (name_size + 3) & ~3   # Round up to the next multiple of 4
                desc = data[i:i+desc_size]
                i += (desc_size + 3) & ~3   # Round up to the next multiple of 4
            except IndexError:
                break
            else:
                self.notes.setdefault(name, []).append((note_type, desc))
        if i < len(data):
            log.warn("Note data in {} section malformed: {} bytes not parseable as note entry.".format(name, len(data) - i))


class XtPropSection (MetadataSection):
    """
        The .xt.prop section contains meta-information about regions of other
        sections in the file, such as whether a region is code or literal
        values, where all the branch targets are, etc.  It consists of a series
        of 12-byte records of the following form:

            4 bytes -- address (32-bit unsigned number)
            4 bytes -- size (32-bit unsigned number)
            4 bytes -- flags (32-bit bitflag)

        Each record's address/size identifies a region of another section in
        the file.  The flags values give information about the data contained
        in that region.  (Any file which has an .xt.prop section should also
        have an .xt.prop.rela section with relocation fixups for all of the
        'address' fields such that they end up pointing to valid section+offset
        addresses.  These relocation fixups are handled the same way as for any
        other section)
    """
    process_relocs = True

    def __init__(self, objfile, index, name, data):
        MetadataSection.__init__(self, objfile, index, name, data)
        self.entries = []
        num_entries = len(data) // 12
        for i in range(num_entries):
            offset = self.get_data_word(i * 12)
            size = self.get_data_word(i * 12 + 4)
            flags = self.get_data_word(i * 12 + 8)
            self.entries.append([offset, size, flags])

    def register_reloc_ptr(self, addr, sym, addend):
        i = addr.offset // 12
        self.entries[i][0] += sym + addend
        debug(3, ".xt.prop relocation @ 0x{:x} (entry {}) -> {!r}".format(addr.offset, i, self.entries[i][0]))

    def apply_annotations(self):
        i = 0
        for addr, size, flags in self.entries:
            if not isinstance(addr, Addr):
                debug(1, "Note: .xt.prop entry {} has not been resolved to a full addr.  Skipping.".format(i))
                continue
            if flags & XTENSA_PROP_LITERAL:
                debug(1, "Annotating {!r} as literal (.xt.prop entry {})".format(addr, i))
                addr.section.register_literal(addr)
            if flags & XTENSA_PROP_INSN:
                debug(1, "Annotating {!r} as code (.xt.prop entry {})".format(addr, i))
                addr.section.annotate(addr, 'type', 'code')
            if flags & XTENSA_PROP_DATA:
                debug(1, "Annotating {!r} as data (.xt.prop entry {})".format(addr, i))
                addr.section.annotate(addr, 'type', 'data')
            if flags & XTENSA_PROP_UNREACHABLE:
                debug(1, "Annotating {!r} as end of code flow (.xt.prop entry {})".format(addr, i))
                addr.section.annotate(addr, 'code_flow_end', True)
            if flags & XTENSA_PROP_INSN_LOOP_TARGET:
                debug(1, "Annotating {!r} as branch (loop) target (.xt.prop entry {})".format(addr, i))
                addr.section.annotate(addr, 'ref', 'branch')
            if flags & XTENSA_PROP_INSN_BRANCH_TARGET:
                debug(1, "Annotating {!r} as branch target (.xt.prop entry {})".format(addr, i))
                addr.section.annotate(addr, 'ref', 'branch')
            i += 1


class XtLitSection (MetadataSection):
    """
        The .xt.lit section contains a list of regions of other sections which
        contain literal data instead of code.  This appears to be effectively
        redundant with the XTENSA_PROP_LITERAL flag in .xt.prop, but we note
        and record the contents of .xt.lit if present anyway, just in case (it
        is possible there might be files without an .xt.prop but with .xt.lit,
        in which case it would still be useful info to have).

        The .xt.lit section consists of a series of 8-byte records of the
        following form:

            4 bytes -- address (32-bit unsigned number)
            4 bytes -- size (32-bit unsigned number)

        Each record's address/size identifies a region of another section in
        the file, and that region of that section should be considered to
        contain literal data words, rather than code.  (Any file which has an
        .xt.lit section should also have an .xt.lit.rela section with
        relocation fixups for all of the 'address' fields such that they end up
        pointing to valid section+offset addresses.  These relocation fixups
        are handled the same way as for any other section)
    """
    process_relocs = True

    def __init__(self, objfile, index, name, data):
        MetadataSection.__init__(self, objfile, index, name, data)
        self.entries = []
        num_entries = len(data) // 8
        for i in range(num_entries):
            offset = self.get_data_word(i * 8)
            size = self.get_data_word(i * 8 + 4)
            self.entries.append([offset, size])

    def register_reloc_ptr(self, addr, sym, addend):
        i = addr.offset // 8
        self.entries[i][0] += sym + addend
        debug(3, ".xt.lit relocation @ 0x{:x} (entry {}) -> {!r}".format(addr.offset, i, self.entries[i][0]))

    def apply_annotations(self):
        i = 0
        for start, size in self.entries:
            if not isinstance(start, Addr):
                debug(1, "Note: .xt.lit entry {} has not been resolved to a full addr.  Skipping.".format(i))
                continue
            for offset in range(0, size, 4):
                addr = start + offset
                debug(1, "Annotating {!r} as literal (.xt.lit entry {})".format(addr, i))
                addr.section.annotate(addr, 'type', 'data')
                addr.section.annotate(addr, 'ref', 'literal')
            i += 1


class StackPseudoSection (Section):
    def __init__(self, function_region):
        objfile = function_region.start.section.objfile
        Section.__init__(self, objfile, None, '(FP)', b'')
        self.function_region = function_region


class ObjectFile:
    label_ref_templates = (
        ('entry_point', True, '.Lfunc{:03}'),
        ('call', True, '.Lfunc{:03}'),
        ('branch', True, '.Lbr{:03}'),
        ('reloc', False, '.Lrel{:03}'),
        ('literal', False, '.Llit{:03}'),
        ('str', False, '.Lstr{:03}'),
    )
    label_type_templates = (
        ('code', '.Lfunc{:03}'),
        ('data', '.Ldata{:03}'),
    )
    default_template = '.Label{:03}'

    def __init__(self, filename, disassembler):
        self.filename = filename
        self.disassembler = disassembler
        self.sections = SortedDict()
        self.sections_byname = {}
        self.symbols = {}

    def code_analysis(self):
        changed = True
        while changed:
            changed = False
            for section in self.sections.values():
                changed = section.code_analysis() or changed
            if changed:
                debug(2, "Code analysis performed changes.  Re-running another iteration.")

    def data_analysis(self):
        for section in self.sections.values():
            section.data_analysis()

    def cleanup(self):
        self.generate_labels()
        for section in self.sections.values():
            section.cleanup()

    def rewrite(self, rewrite_opts):
        for section in self.sections.values():
            section.rewrite(rewrite_opts)

    def generate_labels(self):
        current_counters = {}
        for section in self.sections.values():
            for addr, note in section.annotations.items():
                refs = note.get('ref')
                types = note.get('type', ())
                if not refs:
                    # This location isn't referenced by anything else, no need
                    # for a label.
                    continue
                if section.get_labels(addr):
                    # There's already a label here, no need to auto-generate
                    # one.
                    continue
                template = None
                # First, we try to determine the type of label to give
                # something based on how it's referenced by other things.
                for r, code_ok, t in self.label_ref_templates:
                    if r in refs:
                        if code_ok or not 'code' in types:
                            template = t
                            break
                # If we couldn't figure it out by ref, try to choose based on
                # the type annotation instead.
                if not template:
                    for r, t in self.label_type_templates:
                        if r in types:
                            template = t
                            break
                # If we couldn't figure it out by ref or by type, just give it
                # a generic label.
                if not template:
                    template = self.default_template
                counter = current_counters.setdefault(template, 1)
                section.add_label(addr, template.format(counter))
                current_counters[template] += 1

    def add_section(self, section):
        self.sections[section.index] = section
        self.sections_byname[section.name] = section

    def get_section(self, section):
        if isinstance(section, Section):
            return section
        elif isinstance(section, int):
            return self.sections.get(section)
        else:
            return self.sections_byname.get(str(section))

    def dump(self, writer):
        writer.start_file(self)
        for section in self.sections.values():
            section.dump(writer)
        writer.end_file()

    def get_callmap(self):
        results = {}
        for section in self.sections.values():
            results[section] = section.get_callmap()
        return results

    def disassemble(self, start, end=None):
        return self.disassembler.disassemble(self.filename, start, end)

    def add_symbol(self, index, section, offset, name, symtype):
        sym = Symbol(section, offset, name)
        sym.type = symtype
        self.symbols[index] = sym
        self.symbols[name] = sym

    def get_symbol(self, name):
        return self.symbols.get(name)

    def parse_addr(self, addrspec, name=None):
        basespec = None
        if isinstance(addrspec, int):
            offset = addrspec
        else:
            if '+' in addrspec:
                basespec, offset = addrspec.split('+', 2)
                offset = int(offset, 0)
            elif '-' in addrspec:
                basespec, offset = addrspec.split('-', 2)
                offset = -int(offset, 0)
            else:
                if self.get_section(addrspec) or self.get_symbol(addrspec):
                    basespec = addrspec
                    offset = 0
                else:
                    offset = int(addrspec, 0)
        if basespec:
            section = self.get_section(basespec)
            if section is None:
                base = self.get_symbol(basespec)
                if base is None:
                    raise ValueError("Bad section/symbol name: {!r}".format(basespec))
                addr = base + offset
                addr.name = name
                return addr
        else:
            # We just got a bare offset with no section/symbol name
            if len(self.sections) == 1:
                # We've only got one section defined (probably in --raw mode)
                # so this is OK, we'll just infer it.
                section = next(iter(self.sections.values()))
            else:
                raise ValueError("Must be of the form <name>+<offset>")
        return Addr(section, offset, name)

    def add_manual_symbols(self, specs):
        for (addrspec, syminfo) in specs:
            name, symtype = (syminfo.split() + ['STT_NOTYPE'])[:2]
            try:
                addr = self.parse_addr(addrspec, name or None)
            except ValueError as e:
                log.error("Invalid address for symbol: {!r}: {}".format(addrspec, e))
                continue
            addr.section.annotate(addr, 'manual:symbol', name)
            debug(1, "Adding symbol ({}) for entrypoint at {!r}".format(name, addr))
            self.add_symbol(None, addr.section, addr.offset, name, symtype)

    def add_manual_entrypoints(self, specs):
        for (addrspec, name) in specs:
            try:
                addr = self.parse_addr(addrspec, name or None)
            except ValueError as e:
                log.error("Invalid address for entrypoint: {!r}: {}".format(addrspec, e))
                continue
            addr.section.annotate(addr, 'manual:entrypoint', name)
            debug(1, "Noting function entry point at {!r}".format(addr))
            addr.section.register_entry_point(addr, name=name)
            if name:
                debug(1, "Adding symbol ({}) for entrypoint at {!r}".format(name, addr))
                self.add_symbol(None, addr.section, addr.offset, name, 'STT_FUNC')

    def add_manual_datalocs(self, specs):
        for (addrspec, note_type) in specs:
            try:
                addr = self.parse_addr(addrspec)
            except ValueError as e:
                log.error("Invalid address for data location: {!r}: {}".format(addrspec, e))
                continue
            if '/' in note_type:
                data_type, size = note_type.split('/', 2)
                try:
                    size = int(size, 0)
                except ValueError:
                    size = 0
                if size < 1:
                    log.error("Invalid size for data-location spec (must be a positive integer): {!r}".format(note_type))
                    continue
            else:
                data_type = note_type
                size = 0

            if data_type == 'byte' and size > 1:
                data_type = 'bytes'

            debug(1, "Noting {} data location at {!r}".format(data_type or 'unspecified', addr))
            addr.section.annotate(addr, 'manual:data-location', note_type)
            if not data_type:
                addr.section.annotate(addr, 'type', 'data')
            elif data_type == 'literal':
                if not size:
                    size = 1
                for i in range(size):
                    addr.section.register_literal(addr + (i * 4))
            elif data_type == 'word':
                if not size:
                    size = 1
                for i in range(size):
                    addr.section.register_data(addr + (i * 4), 4, False)
            elif data_type == 'hword':
                if not size:
                    size = 1
                for i in range(size):
                    addr.section.register_data(addr + (i * 2), 2, False)
            elif data_type == 'byte':
                addr.section.register_data(addr, 1, False)
            elif data_type == 'bytes':
                addr.section.annotate(addr, 'type', 'data')
                addr.section.annotate(addr, 'data_type', 'bytes')
                if size:
                    addr.section.annotate(addr, 'data_length', size)
            elif data_type == 'str':
                addr.section.annotate(addr, 'type', 'data')
                addr.section.annotate(addr, 'data_type', 'str')
                if size:
                    addr.section.annotate(addr, 'data_length', size)

    def add_manual_annotations(self, specs):
        for (addrspec, note) in specs:
            try:
                addr = self.parse_addr(addrspec)
            except ValueError as e:
                log.error("Invalid address for annotation: {!r}: {}".format(addrspec, e))
                continue
            addr.section.annotate(addr, 'manual:annotation', note)
            if isinstance(note, str):
                if '=' in note:
                    key, value = note.split('=', 2)
                    try:
                        value = int(value, 0)
                    except ValueError:
                        pass
                else:
                    key = note
                    value = True
                note = {key: value}
            if isinstance(note, dict):
                pass
            else:
                log.error("Bad format/type for annotation: {!r}".format(note))
                continue
            for key, value in note.items():
                debug(1, "Making manual annotation at {!r}: {} = {}".format(addr, key, value))
                addr.section.annotate(addr, key, value)

    def resolve_annotations(self):
        sym_labels = {}
        for sym in self.symbols.values():
            if sym.section and sym.type != 'STT_SECTION':
                sym_labels[sym.name] = sym
        for name in sorted(sym_labels.keys()):
            sym = sym_labels[name]
            debug(1, "Adding label for symbol at {!r}".format(sym))
            sym.section.add_label(sym, name)
            sym.section.annotate(sym, 'symbol', name)
            if sym.type == 'STT_FUNC':
                debug(1, "Noting function entry point at {!r}".format(sym))
                sym.section.register_entry_point(sym, name=name)
        for section in self.sections.values():
            if isinstance(section, (XtPropSection, XtLitSection)):
                section.apply_annotations()


class ObjdumpDisassembler:
    start_re = re.compile('[0-9a-f]+ <.*>:')
    line_re = re.compile(r"\s*(\S*):\s*([0-9a-f]+)\s+(\S+)\s*([^<]*)")

    def __init__(self, objdump_path):
        self.objdump_path = objdump_path

    def objdump_command(self, filename, start, end):
        section = start.section
        section_name = section.name
        cmd = [self.objdump_path, '-Dz', '--section={}'.format(section_name), '--start-address={}'.format(start.offset)]
        if end:
            cmd.append('--stop-address={}'.format(end.offset))
        cmd.append(filename)
        return cmd

    def disassemble(self, filename, start, end=None):
        """
        Invoke objdump to disassemble the bytes in section from start to end
        and parse the resulting output.

        Yields a series of Opcodes.
        """
        section = start.section
        cmd = self.objdump_command(filename, start, end)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1)
        except Exception as e:
            debug(1, "Exception when trying to execute {}".format(cmd), exc_info=sys.exc_info())
            raise DisassemblyFailedException("Cannot invoke {} to disassemble code: {}".format(self.objdump_path, e)) from None
        in_header = True
        for line in proc.stdout.readlines():
            line = bytes2str(line).rstrip()
            if in_header:
                if self.start_re.match(line):
                    in_header = False
                continue
            m = self.line_re.match(line)
            if not m:
                if not line:
                    # Blank lines are not normally expected, but are OK
                    continue
                if self.start_re.match(line):
                    # The disassembler is reporting a symbol which points to
                    # somewhere inside what we're disassembling.  This
                    # shouldn't normally happen, but can happen in the case of
                    # some assmbly-coded stuff, and isn't really a problem.
                    # The symbol's location should already have been noted by
                    # other parts of xtobjdis, so we can just quietly ignore
                    # this.
                    continue
                log.warn("Unrecognized line in disassembly output: {!r}".format(line))
                continue
            op = list(m.groups())
            op_addr = Addr(section, int(op[0], 16))
            op_length = len(op[1]) // 2
            op_instr = op[2]
            op_args = [a.strip() for a in op[3].split(',')]
            #TODO: check hexdata against objdump hexdata
            if op_addr + op_length <= end:
                yield Opcode(op_addr, op_length, op_instr, op_args)
            else:
                debug(2, "Opcode extends past end of disassembly ({!r} + {} is greater than {!r})".format(op_addr, op_length, end))
        if proc.wait() != 0:
            raise DisassemblyFailedException("Disassembly failed (section={}, start={}, end={})".format(section, start, end))


class ObjdumpRawDisassembler (ObjdumpDisassembler):
    def __init__(self, objdump_path, arch):
        ObjdumpDisassembler.__init__(self, objdump_path)
        self.arch = arch

    def objdump_command(self, filename, start, end):
        # We're disassembling a raw file, so just ignore any section specified
        # in start/end and use the offsets..
        cmd = [self.objdump_path, '-Dz', '--target=binary', '-m{}'.format(self.arch), '--start-address={}'.format(start.offset)]
        if end:
            cmd.append('--stop-address={}'.format(end.offset))
        cmd.append(filename)
        return cmd


def print_elf_info(elf):
    march = elf.get_machine_arch()
    if march == '<unknown>':
        # Elftools only has a few hardcoded architectures it knows about, and
        # Xtensa isn't one of them.
        if elf['e_machine'] == 'EM_XTENSA':
            march = 'Xtensa'
    if elf.little_endian:
        endian = "little-endian"
    else:
        endian = "big-endian"
    info(1, "ELF file architecture: {} ({})".format(march, endian))
    info(1, "  {} sections, {} segments".format(elf.num_sections(), elf.num_segments()))
    for k, v in sorted(elf['e_ident'].items()):
        info(1, "  {} = {}".format(k, v))
    info(1, "")


def load_elf_data(objfile, elf):
    objfile.elffile = elf
    objfile.little_endian = elf.little_endian
    for index in range(elf.num_sections()):
        elf_section = elf.get_section(index)
        section_name = bytes2str(elf_section.name)
        section = None
        if elf_section.header.sh_type == 'SHT_NULL':
            debug(1, "Null section (skipped): {} ({})".format(section_name, index))
        elif section_name == '.xt.prop':
            section = XtPropSection(objfile, index, section_name, elf_section.data())
            debug(1, ".xt.prop section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
        elif section_name == '.xt.lit':
            section = XtLitSection(objfile, index, section_name, elf_section.data())
            debug(1, ".xt.lit section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
        elif elf_section.header.sh_type == 'SHT_NOBITS':
            # This is a BSS section (or something else that has no actual valid
            # data contained in the file)
            section = BssSection(objfile, index, section_name, elf_section.header.sh_size)
        elif elf_section.header.sh_type == 'SHT_PROGBITS':
            if elf_section.header['sh_flags'] & SH_FLAGS.SHF_EXECINSTR:
                section = CodeSection(objfile, index, section_name, elf_section.data())
                debug(1, "Code section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
            elif elf_section.header['sh_flags'] & SH_FLAGS.SHF_ALLOC:
                section = DataSection(objfile, index, section_name, elf_section.data())
                debug(1, "Data section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
            else:
                debug(2, "Note: Found SHT_PROGBITS section without SHF_EXECINSTR or SHF_ALLOC ({} ({})): Interpreting as metadata section.".format(section_name, index))
                section = MetadataSection(objfile, index, section_name, elf_section.data())
                debug(1, "Metadata section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
        elif elf_section.header.sh_type == 'SHT_NOTE':
            section = NoteSection(objfile, index, section_name, elf_section.data())
            debug(1, "Note section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
        elif elf_section.header.sh_type in ('SHT_REL', 'SHT_RELA'):
            debug(1, "Relocation section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
        else:
            section = MetadataSection(objfile, index, section_name, elf_section.data())
            debug(1, "Metadata section: {} ({}) -- {} bytes of data".format(section_name, index, len(elf_section.data())))
        if section is not None:
            section.sh_type = elf_section.header.sh_type
            section.sh_entsize = elf_section.header.sh_entsize
            for attr, flaginfo in SECTION_FLAG_ATTRS.items():
                setattr(section, attr, bool(elf_section.header.sh_flags & flaginfo[0]))
            objfile.add_section(section)
    symtab = elf.get_section_by_name(b'.symtab')
    if not symtab:
        log.warning("File has no symbol table section ('.symtab').")
    else:
        debug(1, "Processing symtab: {} symbols found".format(symtab.num_symbols()))
        for index in range(symtab.num_symbols()):
            elf_sym = symtab.get_symbol(index)
            name = bytes2str(elf_sym.name)
            debug(2, "Symbol {}: {!r} (section={}, type={}, value=0x{:08x})".format(index, name, elf_sym.entry['st_shndx'], elf_sym.entry['st_info']['type'], elf_sym.entry['st_value']))
            if elf_sym.entry['st_shndx'] == 'SHN_UNDEF':
                section = None
            else:
                section = objfile.get_section(elf_sym.entry['st_shndx'])
                if not name and section:
                    name = section.name
            offset = elf_sym.entry['st_value']
            objfile.add_symbol(index, section, offset, name, elf_sym.entry['st_info']['type'])
    for elf_section in elf.iter_sections():
        if elf_section.header.sh_type in ('SHT_REL', 'SHT_RELA'):
            rel_section_name = bytes2str(elf_section.name)
            section_name = '.' + rel_section_name.split('.', 2)[2]
            section = objfile.get_section(section_name)
            if section is None:
                log.warn("Cannot find section {!r}.  Ignoring relocations in {!r}".format(section_name, rel_section_name))
                continue
            elif not section.process_relocs:
                debug(1, "Skipping relocations for {}...".format(section.name))
                continue
            debug(1, "Processing relocations for {} ({})...".format(section.name, rel_section_name))
            for rel in elf_section.iter_relocations():
                r_info_type = rel['r_info_type']
                addr = Addr(section, rel['r_offset'])
                sym = objfile.symbols.get(rel['r_info_sym'])
                if sym is None:
                    debug(1, "Reloc at {!r}: symbol {} not loaded.  Skipping.".format(addr, rel['r_info_sym']))
                    continue
                addend = rel.entry.get('r_addend', 0)
                if r_info_type in (R_XTENSA_32, R_XTENSA_PLT):
                    debug(2, "Reloc: R_XTENSA_32 {!r} = {}+0x{:x}".format(addr, sym, addend))
                    relptr = section.register_reloc_ptr(addr, sym, addend)
                elif r_info_type == R_XTENSA_SLOT0_OP:
                    debug(2, "Reloc: R_XTENSA_SLOT0_OP {!r} = {}+0x{:x}".format(addr, sym, addend))
                    section.add_slot_reloc(addr, 0, sym, addend)
                elif r_info_type == R_XTENSA_ASM_EXPAND:
                    # These are really just an annotation, not a meaningful
                    # relocation fixup.  It's possible there's some useful
                    # information to be gleaned here in some cases, but for now
                    # we just ignore them.
                    debug(2, "(Ignoring R_XTENSA_ASM_EXPAND reloc at {!r})".format(addr))
                elif r_info_type == R_XTENSA_NONE:
                    # As best I can determine, R_XTENSA_NONE happens when the
                    # linker puts things together in such a way that what was
                    # previously a relocation is no longer needed (instead of
                    # removing it entirely, it just sets it to R_XTENSA_NONE),
                    # so these can be safely ignored.
                    debug(2, "(Ignoring R_XTENSA_NONE reloc at {!r})".format(addr))
                else:
                    log.warn("Unexpected relocation type at {!r} (type={} reloc={}+0x{:x}).  Ignored.".format(addr, r_info_type, sym, addend))


def load_raw_data(objfile, f, raw_offset, section_name):
    objfile.elffile = None
    objfile.little_endian = True  #TODO: make this configurable
    section = CodeSection(objfile, 0, section_name, f.read())
    section.base_address = raw_offset
    section.sh_type = 'SHT_PROGBITS'
    section.sh_entsize = 0
    section.flag_alloc = True
    section.flag_writable = False
    section.flag_exec = True
    section.flag_mergeable = False
    section.flag_strings = False
    section.flag_group = False
    section.flag_tls = False
    objfile.add_section(section)


def parse_addr_spec(string, default_section_name=None):
    if ':' in string:
        string, name = string.split(':', 2)
    else:
        name = None
    if '+' in string:
        section, offset = string.split('+', 2)
    else:
        section = default_section_name
        offset = string
    offset = int(offset, 0)
    if offset < 0:
        raise ValueError("Offset must be nonnegative")
    if section is None:
        raise ValueError("No section specified")
    return (section, offset, name)


def filename_match(filename, template_filename):
    if (os.sep + filename).endswith(os.sep + template_filename):
        return True
    if (os.sep + os.path.realpath(filename)).endswith(os.sep + template_filename):
        return True
    return False


def generate_hash(filename):
    hasher = hashlib.sha256()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()


class Fixups:
    @classmethod
    def load_from_file(cls, fixupfile_name, objfile_name):
        import yaml

        filehash = None
        filename = os.path.normpath(objfile_name)
        best_match = None
        best_match_filename = ''
        default_fixups = None

        with open(fixupfile_name, 'r') as f:
            for fixups in yaml.safe_load_all(f):
                if not isinstance(fixups, dict):
                    log.warning("Malformed fixups section in {} (skipped)".format(fixupfile_name))
                    continue
                fixups_filename = fixups.get('filename', '')
                if fixups_filename:
                    fixups_filename = os.path.normpath(fixups_filename)
                fixups_filehash = fixups.get('filehash')
                if fixups_filehash:
                    if filehash is None:
                        try:
                            filehash = generate_hash(objfile_name)
                        except (FileNotFoundError, IOError) as e:
                            # If we can't read the source file, the program will
                            # bomb out later anyway.  For now, just pick a value
                            # that will never match.
                            debug(1, 'load_fixups: Cannot read object file: {}'.format(e))
                            filehash = False
                    if filehash == fixups_filehash:
                        if fixups_filename and not filename_match(filename, fixups_filename):
                            debug(1, 'Note: Fixups found with matching filehash ({}), but filename does not match.  Using them anyway.'.format(fixups_filename))
                        else:
                            debug(2, 'Using fixups matching filehash ({}).'.format(fixups_filename))
                        return cls(fixups)
                    elif filename_match(filename, fixups_filename):
                        debug(2, 'Found fixups with potentially matching filename ({}) but hash does not match.  Ignoring.'.format(fixups_filename))
                elif fixups_filename:
                    if filename_match(filename, fixups_filename):
                        debug(2, 'Found fixups with potentially matching filename ({}).'.format(fixups_filename))
                        if len(fixups_filename) > len(best_match_filename):
                            best_match = fixups
                            best_match_filename = fixups_filename
                else:
                    if default_fixups is None:
                        default_fixups = fixups
        if best_match:
            debug(2, 'Using fixups with best filename match ({}).'.format(best_match['filename']))
            return cls(best_match)
        if default_fixups:
            debug(2, 'No fixups filename or hash match.  Using default fixups entry.')
            return cls(default_fixups)
        debug(1, 'No appropriate fixups found in {!r} for input file {!r}'.format(fixupfile_name, filename))
        return None

    def __init__(self, rawdata):
        self.rawdata = rawdata
        self.name = rawdata.get('filename')
        if not self.name:
            self.name = rawdata.get('filehash', '(default)')

    def __str__(self):
        return self.name

    def _addr_list(self, listname):
        result = []
        rawlist = self.rawdata.get(listname, [])
        if not isinstance(rawlist, list):
            rawlist = [rawlist]
        for entry in rawlist:
            if isinstance(entry, dict):
                pass
            elif isinstance(entry, (str, int)):
                entry = {str(entry): ''}
            else:
                log.error("Malformed entry in {!r} list (YAML interpreted as {!r}).  Ignored.".format(listname, entry))
                continue
            result.extend(entry.items())
        return result

    @property
    def symbols(self):
        return self._addr_list('symbols')

    @property
    def entrypoints(self):
        return self._addr_list('entrypoints')

    @property
    def data_locations(self):
        return self._addr_list('data-locations')

    @property
    def annotations(self):
        return self._addr_list('annotations')

    def apply(self, objfile):
        objfile.add_manual_symbols(self.symbols)
        objfile.add_manual_entrypoints(self.entrypoints)
        objfile.add_manual_datalocs(self.data_locations)
        objfile.add_manual_annotations(self.annotations)


class DumpWriter:
    section_type_map = {
        'SHT_PROGBITS': '@progbits',
        'SHT_NOBITS': '@nobits',
        'SHT_NOTE': '@note',
        'SHT_INIT_ARRAY': '@init_array',
        'SHT_FINI_ARRAY': '@fini_array',
        'SHT_PREINIT_ARRAY': '@preinit_array',
    }

    symbol_type_map = {
        'STT_FUNC': '@function',
        'STT_GNU_IFUNC': '@gnu_indirect_function',
        'STT_OBJECT': '@object',
        'STT_TLS': '@tls_object',
        'STT_COMMON': '@common',
    }

    def __init__(self, outfile):
        self.outfile = outfile
        self.output_annotations = False
        self.output_hexdump = True
        self.output_opcode_notes = True
        self.output_empty_sections = False
        self.line_fmt = "{:62} {}"
        self.asmline_fmt = "{:11} {:12} {}"
        self.data_comment_fmt = "# {:>4x}: {}"
        self.label_width = 11
        self.hexdata_chunk_size = 4
        self.spacer_lines = 0

    def dump(self, obj):
        obj.dump(self)

    def start_file(self, objfile):
        self.objfile = objfile

    def end_file(self):
        pass

    def start_section(self, section):
        self.section = section
        self.addr = Addr(section, 0)
        self.annotations = section.annotations
        self.note_locs = sorted(self.annotations.keys()) + [Addr(section, len(section.data))]
        self.nl = 0

        self.spacer_line()
        args = [section.name, '"{}"'.format(section.flags_str())]
        typestr = self.section_type_map.get(section.sh_type)
        if typestr:
            args.append(typestr)
        if section.sh_entsize:
            args.append(str(section.sh_entsize))
        self.asm_line(None, 0, '.section', ', '.join(args))
        self.spacer_line()

    def end_section(self):
        while self.nl < len(self.annotations):
            note_addr = self.note_locs[self.nl]
            for label in sorted(self.annotations[note_addr].get('label', ())):
                self.emit_label(label, note_addr)
            self.emit_annotation(note_addr)
            self.nl += 1

    def start_function(self, addr):
        self.check_addr(addr)
        self.comment('Function @ {}+0x{:x}'.format(addr.section.name, addr.offset))

    def check_addr(self, addr):
        if self.addr == addr:
            return True
        if self.addr > addr:
            self.spacer_line()
            log.warning("Apparently overlapping regions: New position {!r} is before current position {!r}".format(addr, self.addr))
            self.output_line("### WARNING: Next instruction is before current position!")
            self.asm_line(None, 0, '.org', '0x{:x}'.format(addr.offset))
            self.nl = bisect.bisect_left(self.note_locs, addr)
        elif self.addr < addr:
            # Check to make sure there aren't any notes/labels in the region
            # we're skipping over.  If there are, we should skip forward to
            # each in turn and then print it, before finally skipping to the
            # final addr.
            while self.note_locs[self.nl] < addr:
                note_addr = self.note_locs[self.nl]
                for label in sorted(self.annotations[note_addr].get('label', ())):
                    self.emit_label(label, note_addr)
                self.emit_annotation(note_addr)
                self.nl += 1
            if (addr - self.addr < 4) and (addr.offset % 4 == 0):
                # If we're just skipping to the next 32-bit word boundary,
                # indicate this by using a '.balign' directive instead, so it's
                # more obvious what's going on.
                #TODO: we should base this on the section's specified alignment instead of always assuming 4
                self.asm_line(None, 0, '.balign', '4')
            else:
                # Otherwise, skip forward with '.skip'.  This should generally
                # only happen if the previous region was a padding region (full
                # of zeroes).
                self.spacer_line()
                self.asm_line(None, 0, '.skip', str(addr - self.addr))
        self.addr = addr
        return False

    def output_line(self, text, spacers=True):
        if spacers:
            self.outfile.write(self.spacer_lines * '\n')
            self.spacer_lines = 0
        self.outfile.write("{}\n".format(text.rstrip()))

    def warning(self, text):
        self.output_line("### WARNING: {}".format(text))

    def comment(self, text):
        self.output_line("# {}".format(text))

    def spacer_line(self, count=1):
        self.spacer_lines = max(self.spacer_lines, count)

    def pre_emit_label(self, label, addr=None):
        sym = self.objfile.get_symbol(str(label))
        if sym:
            self.asm_line(None, 0, '.global', label)
            symtype = self.symbol_type_map.get(sym.type, sym.type)
            self.asm_line(None, 0, '.type', "{}, {}".format(label, symtype))

    def emit_label(self, label, addr=None):
        self.pre_emit_label(label, addr)
        if addr is None or addr == self.addr:
            # Label corresponds to our current position.  Nothing special to do
            # here.
            self.output_line("{}:".format(label))
        elif addr < self.addr:
            # Oops.. we missed it because an instruction (or something) took us
            # past the label's address.
            self.output_line(self.asmline_fmt.format(label, '=', '.-{}  ### WARNING: label not on instruction boundary!'.format(self.addr - addr)))
        else:
            # This label is somewhere ahead of where we are.  Assume we're
            # being called because we're skipping past its location, so we need
            # to print it out now.  Just print an absolute address for this.
            self.output_line(self.asmline_fmt.format(label, '=', '0x{:x}'.format(addr.offset)))

    def emit_annotation(self, addr):
        if not self.output_annotations:
            return
        ann = self.annotations[addr]
        for key in sorted(ann.keys()):
            value = ', '.join(sorted(str(a) for a in ann[key]))
            self.output_line("# Ann: {:x}: {} = {}".format(addr.offset, key, value))

    def asm_line(self, addr, length, instr, argstr, output_hexdump=True, check_addr=True):
        output_hexdump = output_hexdump and self.output_hexdump
        if addr is not None:
            if check_addr:
                self.check_addr(addr)

            while self.note_locs[self.nl] < addr:
                note_addr = self.note_locs[self.nl]
                for label in sorted(self.annotations[note_addr].get('label', ())):
                    self.emit_label(label, note_addr)
                self.emit_annotation(note_addr)
                self.nl += 1
            label = ''
            if self.note_locs[self.nl] == addr:
                note_addr = self.note_locs[self.nl]
                self.emit_annotation(note_addr)
                labels = sorted(self.annotations[note_addr].get('label', ()))
                if labels:
                    for label in labels[:-1]:
                        self.emit_label(label, note_addr)
                    label = labels[-1] + ':'
                    self.pre_emit_label(labels[-1], note_addr)
                self.nl += 1
            if output_hexdump:
                data = self.section.data[addr:addr + min(length, self.hexdata_chunk_size)]
                hexdata = ''.join('{:02x}'.format(b) for b in data)
                comment = self.data_comment_fmt.format(addr.offset, hexdata)
            else:
                comment = ''
        else:
            label = ''
            comment = ''
        if len(label) > self.label_width:
            self.output_line(label)
            label = ''
        asmline = self.asmline_fmt.format(label, instr, argstr)
        self.output_line(self.line_fmt.format(asmline, comment))
        if output_hexdump and length > self.hexdata_chunk_size:
            data = self.section.data[addr:addr + length]
            for i in range(self.hexdata_chunk_size, length, self.hexdata_chunk_size):
                chunk = data[i:min(i + self.hexdata_chunk_size, length)]
                hexdata = ''.join('{:02x}'.format(b) for b in chunk)
                comment = self.data_comment_fmt.format(addr.offset + i, hexdata)
                self.output_line(self.line_fmt.format('', comment))
        if addr is not None:
            self.addr = addr + length

    def opcode(self, opcode):
        argstr = opcode.argstr()
        if self.output_opcode_notes:
            for n in opcode.notes:
                argstr += ' /* {} */'.format(n)
        self.asm_line(opcode.addr, opcode.length, opcode.instr, argstr)


class SimpleFormatter (logging.Formatter):
    def formatMessage(self, record):
        return str(record.msg)

    def format(self, record):
        text = logging.Formatter.format(self, record)
        if record.levelno == logging.INFO:
            return text
        else:
            prefixed = ('[{}] {}'.format(record.levelname, line) for line in text.split('\n'))
            return '\n'.join(prefixed)


def print_elf_format_error(args, f):
    log.error("{} does not appear to be an ELF object (.o) file.".format(args.filename))
    f.seek(0)
    magic = f.read(8)
    if magic == b'!<arch>\n':

        # Try to figure out the right command for 'ld' to use in the example.
        # Start with our configured objdump command.  Strip off any leading
        # path just to make things cleaner.
        objdump_cmd = os.path.basename(args.objdump)
        if 'objdump' in objdump_cmd:
            # Assume that the name of the 'ld' executable will be the same as
            # the 'objdump' executable, but with 'ld' instead of 'objdump'.
            ld_cmd = objdump_cmd.replace('objdump', 'ld')
        elif 'objdump' in DEFAULT_OBJDUMP:
            # The configured objdump executable isn't in an obvious format, so
            # fall back to basing it on our default objdump command.
            ld_cmd = DEFAULT_OBJDUMP.replace('objdump', 'ld')
        else:
            # Even our default isn't obvious.  Oh well, fall back to a
            # reasonable (or at least hopefully clear enough that the user can
            # figure out what's meant) guess instead.
            ld_cmd = "xtensa-lx106-elf-ld"

        info(0, "Note: It appears this file may be a library (.a) instead of an object (.o) file")
        info(0, "  If this is the case, you have two options:")
        info(0, "  1) Extract the individual .o files from the library using ar:")
        info(0, "       ar x \"{}\"".format(args.filename))
        info(0, "     and then disassemble them individually.")
        info(0, "  2) Link everything in the library into a single .o file:")
        info(0, "       {} --relocatable --whole-archive \"{}\" -o outputfile.o".format(ld_cmd, args.filename))
        info(0, "     and then disassemble that file.")
        info(0, "     (Note that if you want to you can even specify multiple libraries to")
        info(0, "     link them all together into a single .o as well)")


def write_callmap(objfile, filename):
    result = {}
    for section, funcs in objfile.get_callmap().items():
        section_info = {}
        for f, targets in funcs.items():
            func_name = str(f.start)
            func_offset = f.start.offset
            is_sym = bool(section.annotations.get(f.start, {}).get('symbol'))
            calls = []
            for src, dst in targets:
                calls.append({'opcode_offset': src.offset - func_offset, 'target': str(dst)})
            funcdata = {'offset': func_offset, 'global_name': is_sym, 'calls': calls}
            section_info[func_name] = funcdata
        if section_info:
            result[section.name] = section_info
    callmap = [{'filename': objfile.filename, 'functions': result}]
    with open(filename, 'w') as f:
        json.dump(callmap, f, sort_keys=True, indent=4)


if __name__ == '__main__':
    h = logging.StreamHandler()
    h.setFormatter(SimpleFormatter())
    logging.root.addHandler(h)

    parser = argparse.ArgumentParser(prog='xtobjdis', description='ELF object file disassembler for the Xtensa ISA')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(VERSION_STRING))
    parser.add_argument('filename', metavar='OBJFILE', type=str,
                       help="ELF object (.o) file to disassemble")
    parser.add_argument('--raw', metavar='OFFSET[:NAME]', type=str, help="Treat OBJFILE as a raw (not ELF) dump (assume it's loaded at start address OFFSET, and give it section name NAME in the disassembled output)")
    parser.add_argument('--entrypoint', metavar='ADDR[:NAME]', action='append', default=[], help="Treat ADDR as a function entry point (optionally named NAME)")
    parser.add_argument('--verbose', '-v', action='count', default=0,
                       help="Increase output verbosity (can be specified multiple times)")
    parser.add_argument('--quiet', '-q', action='count', default=0,
                       help="Do not print info messages (use twice to also suppress warnings)")
    parser.add_argument('--annotations', '-a', action='count', default=0,
                       help="Add detailed annotation comments to assembly output")
    parser.add_argument('--nohex', action='store_true',
                       help="Do not print hex-dump comments on each line")
    parser.add_argument('--noopnotes', action='store_true',
                       help="Do not print comments about opcode arguments")
    parser.add_argument('--empty-sections', action='store_true',
                       help="Print a .section entry even for sections with no contents")
    parser.add_argument('--callmap', metavar='MAPFILE', type=str,
                       help="Write call-map data to MAPFILE")
    parser.add_argument('--objdump', metavar='CMD', type=str,
                       help="Full pathname of the objdump command to use")
    parser.add_argument('--fixups', metavar='FIXUPFILE', type=str,
                       help="Load fixup info from FIXUPFILE")
    parser.add_argument('--hash', action='store_true',
                       help="Do not disassemble the file, just print its hash")
    parser.add_argument('--rewrite-inline-literals', action='store_true',
                       help="Represent literals directly in movi/call0/etc instead of using l32r")
    parser.add_argument('--rewrite-remove-dotn', action='store_true',
                       help="Strip trailing '.n' from narrow opcodes")
    parser.add_argument('--rewrite-remove-padding', action='store_true',
                       help="Remove '.skip' padding following jumps, etc")
    parser.add_argument('--rewrite-sr-as-arg', action='store_true',
                       help="Represent the special register as a second argument to RSR/WSR/XSR instead of part of the instruction name")
    parser.add_argument('--rewrite-or-as-mov', action='store_true',
                       help="Represent 'or r1, r2, r2' as 'mov r1, r2' instead")
    parser.add_argument('--rewrite-a1-as-sp', action='store_true',
                       help="Represent register a1 using its alternate name of 'sp'")
    parser.add_argument('--rewrite-as-source', action='store_true',
                       help="Apply all common formatting idioms to make the result more source-code-like (equivalent to '--rewrite-inline-literals --rewrite-remove-dotn --rewrite-sr-as-arg --rewrite-or-as-mov --rewrite-a1-as-sp')")

    args = parser.parse_args()

    if args.hash:
        print("filehash: {}".format(generate_hash(args.filename)))
        sys.exit(0)

    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    elif args.quiet > 1:
        logging.root.setLevel(logging.ERROR)
    elif args.quiet:
        logging.root.setLevel(logging.WARNING)
    else:
        logging.root.setLevel(logging.INFO)
    info_level = args.verbose
    debug_level = args.verbose - 1

    if not args.objdump:
        args.objdump = os.environ.get(OBJDUMP_ENV_VAR, '')
        debug(3, "no objdump specified.  {} environment setting is {!r}".format(OBJDUMP_ENV_VAR, args.objdump))
    if not args.objdump:
        args.objdump = DEFAULT_OBJDUMP
        debug(3, "no objdump specified on command line or in environment.  Defaulting to {!r}".format(args.objdump))
    install_directory = os.path.abspath(os.path.dirname(sys.argv[0]))
    if not is_pathname(args.objdump):
        debug(3, "objdump setting ({!r}) is not a full path spec.  Searching standard locations...".format(args.objdump))
        for path in [install_directory] + os_path():
            filename = os.path.join(path, args.objdump)
            if os.path.exists(filename):
                debug(3, "{!r} exists! Using it for objdump.".format(filename))
                args.objdump = filename
                break
            else:
                debug(3, "{!r} does not exist...")
    if not is_pathname(args.objdump):
        log.error("Unable to find {!r} in either {} or the system path.  Please specify the location of an appropriate objdump executable with the '--objdump' option.".format(args.objdump, install_directory))
        sys.exit(1)

    if args.raw is not None:
        rawinfo = args.raw.split(':', 2)
        try:
            raw_offset = int(rawinfo[0], 0)
        except ValueError:
            raw_offset = -1
        if raw_offset < 0:
            log.error("Invalid offset for --raw ({!r}).  Must be a nonnegative integer.".format(rawinfo[0]))
            sys.exit(1)
        if len(rawinfo) < 2:
            raw_name = '.text'
        else:
            raw_name = rawinfo[1]
    else:
        raw_offset = None
        raw_name = None

    if args.entrypoint:
        for i in range(len(args.entrypoint)):
            e = args.entrypoint[i].split(':', 2)
            if len(e) < 2:
                e.append('')
            args.entrypoint[i] = e

    fixups = None
    if args.fixups:
        try:
            fixups = Fixups.load_from_file(args.fixups, args.filename)
        except (FileNotFoundError, IOError) as e:
            log.error("Unable to read fixups file {!r}: {}".format(args.fixups, e))
    rewrite_opts = {
        'inline_literals': args.rewrite_inline_literals,
        'remove_dotn': args.rewrite_remove_dotn,
        'remove_padding': args.rewrite_remove_padding,
        'sr_as_arg': args.rewrite_sr_as_arg,
        'a1_as_sp': args.rewrite_a1_as_sp,
        'or_as_mov': args.rewrite_or_as_mov,
    }
    if args.rewrite_as_source:
        rewrite_opts['inline_literals'] = True
        rewrite_opts['remove_dotn'] = True
        rewrite_opts['remove_padding'] = True
        rewrite_opts['sr_as_arg'] = True
        rewrite_opts['a1_as_sp'] = True
        rewrite_opts['or_as_mov'] = True

    info(1, "xtobjdump version {}".format(VERSION_STRING))
    info(1, "  objdump={}".format(args.objdump))
    info(1, "  hexdump={}".format(not args.nohex))
    info(1, "  opnotes={}".format(not args.noopnotes))
    info(1, "  empty_sections={}".format(not args.empty_sections))
    info(1, "  annotations={}".format(args.annotations))
    if args.raw:
        info(1, "  raw=yes ({})".format(args.raw))
    else:
        info(1, "  raw=no")
    info(1, "  fixups_file={}".format(args.fixups))
    info(1, "  fixups={}".format(fixups))
    info(1, "Disassembling: {}".format(args.filename))
    info(1, "")

    dw = DumpWriter(sys.stdout)
    dw.output_hexdump = not args.nohex
    dw.output_opcode_notes = not args.noopnotes
    dw.output_empty_sections = bool(args.empty_sections)
    dw.output_annotations = bool(args.annotations)

    with open(args.filename, 'rb') as f:
        if args.raw:
            disassembler = ObjdumpRawDisassembler(args.objdump, 'xtensa')
        else:
            try:
                elf = ELFFile(f)
            except ELFError:
                print_elf_format_error(args, f)
                sys.exit(1)
            disassembler = ObjdumpDisassembler(args.objdump)
        try:
            objfile = ObjectFile(args.filename, disassembler)
            if args.raw:
                debug(1, "=== Loading RAW Data...")
                load_raw_data(objfile, f, raw_offset, raw_name)
            else:
                print_elf_info(elf)
                debug(1, "=== Loading ELF Data...")
                load_elf_data(objfile, elf)
            debug(1, "=== Applying manual annotations from command line...")
            objfile.add_manual_entrypoints(args.entrypoint)
            if fixups:
                debug(1, "=== Applying manual annotations from fixups file...")
                fixups.apply(objfile)
            debug(1, "=== Resolving annotations...")
            objfile.resolve_annotations()
            debug(1, "=== Starting code analysis phase...")
            objfile.code_analysis()
            debug(1, "=== Starting data analysis phase...")
            objfile.data_analysis()
            debug(1, "=== Starting cleanup phase...")
            objfile.cleanup()
            debug(1, "=== Starting rewriting phase...")
            objfile.rewrite(rewrite_opts)
            debug(1, "=== Analysis complete.")
            dw.dump(objfile)
            if args.callmap:
                debug(1, "=== Writing callmap...")
                write_callmap(objfile, args.callmap)
        except BrokenPipeError:
            pass
        except XtobjdisException as e:
            log.error(e)
            sys.exit(1)
