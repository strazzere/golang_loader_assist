"""golang_loader_assist.py: Help IDA Pro do some golang reversing."""

__author__ = "Tim 'diff' Strazzere"
__copyright__ = "Copyright 2016, Red Naga"
__license__ = "GPL"
__version__ = "1.2"
__email__ = ["strazz@gmail.com"]

from idautils import *
from idc import *
import idaapi
import sys
import string

#
# Constants
#
DEBUG = False

#
# Utility functions
#
def info(formatted_string):
    print formatted_string

def error(formatted_string):
    print 'ERROR - %s' % formatted_string

def debug(formatted_string):
    if DEBUG:
        print 'DEBUG - %s' % formatted_string

#
# String defining fuctionality
#

# Indicators of string loads
# mov     ebx, offset aWire ; "wire" # Get string
# mov     [esp], ebx
# mov     dword ptr [esp+4], 4 # String length

# mov     ebx, offset unk_8608FD5 # Get string
# mov     [esp+8], ebx
# mov     dword ptr [esp+0Ch], 0Eh # String length

# mov     ebx, offset unk_86006E6 # Get string
# mov     [esp+10h], ebx
# mov     dword ptr [esp+14h], 5 # String length

# mov     ebx, 861143Ch
# mov     dword ptr [esp+0F0h+var_E8+4], ebx
# mov     [esp+0F0h+var_E0], 19h

# Found in newer versions of golang binaries

# lea     rax, unk_8FC736
# mov     [rsp+38h+var_18], rax
# mov     [rsp+38h+var_10], 1Dh

# lea     rdx, unk_8F6E82
# mov     [rsp+40h+var_38], rdx
# mov     [rsp+40h+var_30], 13h

# lea     eax, unk_82410F0
# mov     [esp+94h+var_8C], eax
# mov     [esp+94h+var_88], 2


# Currently it's normally ebx, but could in theory be anything - seen ebp
VALID_REGS = ['eax', 'ebx', 'ebp', 'rax', 'rcx', 'r10', 'rdx']

# Currently it's normally esp, but could in theory be anything - seen eax
VALID_DEST = ['esp', 'eax', 'ecx', 'edx', 'rsp']

# TODO : Extract patterns
def is_string_load(addr):
    patterns = []
    # Check for first parts instruction and what it is loading -- also ignore function pointers we may have renamed
    if (GetMnem(addr) != 'mov' and GetMnem(addr) != 'lea') and (GetOpType(addr, 1) != 2 or GetOpType(addr, 1) != 5) or GetOpnd(addr, 1)[-4:] == '_ptr':
        return False

    # Validate that the string offset actually exists inside the binary
    if idaapi.get_segm_name(GetOperandValue(addr, 1)) is None:
        return False

    # Could be unk_, asc_, 'offset ', XXXXh, ignored ones are loc_ or inside []
    if GetOpnd(addr, 0) in VALID_REGS and not ('[' in GetOpnd(addr, 1) or 'loc_' in GetOpnd(addr, 1)) and (('offset ' in GetOpnd(addr, 1) or 'h' in GetOpnd(addr, 1)) or ('unk' == GetOpnd(addr, 1)[:3])):
        from_reg = GetOpnd(addr, 0)
        # Check for second part
        addr_2 = FindCode(addr, SEARCH_DOWN)
        try:
            dest_reg = GetOpnd(addr_2, 0)[GetOpnd(addr_2, 0).index('[') + 1:GetOpnd(addr_2, 0).index('[') + 4]
        except ValueError:
            return False
        if GetMnem(addr_2) == 'mov' and dest_reg in VALID_DEST and ('[%s' % dest_reg) in GetOpnd(addr_2, 0) and GetOpnd(addr_2, 1) == from_reg:
            # Check for last part, could be improved
            addr_3 = FindCode(addr_2, SEARCH_DOWN)
            # GetOpType 1 is a register, potentially we can just check that GetOpType returned 5?
            if GetMnem(addr_3) == 'mov' and (('[%s+' % dest_reg) in GetOpnd(addr_3, 0) or GetOpnd(addr_3, 0) in VALID_DEST) and 'offset ' not in GetOpnd(addr_3, 1) and 'dword ptr ds' not in GetOpnd(addr_3, 1) and GetOpType(addr_3, 1) != 1 and GetOpType(addr_3, 1) != 2 and GetOpType(addr_3, 1) != 4:
                try:
                    dumb_int_test = GetOperandValue(addr_3, 1)
                    if dumb_int_test > 0 and dumb_int_test < sys.maxsize:
                        return True
                except ValueError:
                    return False

    return False

def create_string(addr, string_len):
    if idaapi.get_segm_name(addr) is None:
        debug('Cannot load a string which has no segment - not creating string @ 0x%02x' % addr)
        return False

    debug('Found string load @ 0x%x with length of %d' % (addr, string_len))
    # This may be overly aggressive if we found the wrong area...
    if GetStringType(addr) is not None and GetString(addr) is not None and len(GetString(addr)) != string_len:
        debug('It appears that there is already a string present @ 0x%x' % addr)
        MakeUnknown(addr, string_len, DOUNK_SIMPLE)

    if GetString(addr) is None and MakeStr(addr, addr + string_len):
        return True
    else:
        # If something is already partially analyzed (incorrectly) we need to MakeUnknown it
        MakeUnknown(addr, string_len, DOUNK_SIMPLE)
        if MakeStr(addr, addr + string_len):
            return True
        debug('Unable to make a string @ 0x%x with length of %d' % (addr, string_len))

    return False

def create_offset(addr):
    if OpOff(addr, 1, 0):
        return True
    else:
        debug('Unable to make an offset for string @ 0x%x ' % addr)

    return False

def strings_init():
    strings_added = 0
    retry = []
    text_seg = get_text_seg()
    if text_seg is None:
        debug('Failed to get text segment')
        return strings_added

    # This may be inherently flawed as it will only search for defined functions
    # and as of IDA Pro 6.95 it fails to autoanalyze many GO functions, currently
    # this works well since we redefine/find (almost) all the functions prior to
    # this being used. Could be worth a strategy rethink later one or on diff archs
    for addr in Functions(text_seg.startEA, text_seg.endEA):
        name = GetFunctionName(addr)

        end_addr = Chunks(addr).next()[1]
        if(end_addr < addr):
            error('Unable to find good end for the function %s' % name)
            pass

        debug('Found function %s starting/ending @ 0x%x 0x%x' %  (name, addr, end_addr))

        while addr <= end_addr:
            if is_string_load(addr):
                if 'rodata' not in idaapi.get_segm_name(addr) and 'text' not in idaapi.get_segm_name(addr):
                    debug('Should a string be in the %s section?' % idaapi.get_segm_name(addr))
                string_addr = GetOperandValue(addr, 1)
                addr_3 = FindCode(FindCode(addr, SEARCH_DOWN), SEARCH_DOWN)
                string_len = GetOperandValue(addr_3, 1)
                if create_string(string_addr, string_len):
                    if create_offset(addr):
                        strings_added += 1
                else:
                    # There appears to be something odd that goes on with IDA making some strings, always works
                    # the second time, so lets just force a retry...
                   retry.append((addr, string_addr, string_len))

                # Skip the extra mov lines since we know it won't be a load on any of them
                addr = FindCode(addr_3, SEARCH_DOWN)
            else:
                addr = FindCode(addr, SEARCH_DOWN)

    for instr_addr, string_addr, string_len in retry:
        if create_string(string_addr, string_len):
            if create_offset(instr_addr):
                strings_added += 1
        else:
            error('Unable to make a string @ 0x%x with length of %d for usage in function @ 0x%x' % (string_addr, string_len, instr_addr))

    return strings_added

#
# Function defining methods
#


def get_text_seg():
    #   .text found in PE & ELF binaries, __text found in macho binaries
    return _get_seg(['.text', '__text'])

def get_gopclntab_seg():
    #   .gopclntab found in PE & ELF binaries, __gopclntab found in macho binaries
    return _get_seg(['.gopclntab', '__gopclntab'])

def _get_seg(possible_seg_names):
    seg = None
    for seg_name in possible_seg_names:
        seg = idaapi.get_segm_by_name(seg_name)
        if seg:
            return seg

    return seg

# Indicators of runtime_morestack
# mov     large dword ptr ds:1003h, 0 # most I've seen
# mov     qword ptr ds:1003h, 0 # some

def is_simple_wrapper(addr):
    if GetMnem(addr) == 'xor' and GetOpnd(addr, 0) == 'edx' and  GetOpnd(addr, 1) == 'edx':
        addr = FindCode(addr, SEARCH_DOWN)
        if GetMnem(addr) == 'jmp' and GetOpnd(addr, 0) == 'runtime_morestack':
            return True

    return False

def create_runtime_ms():
    debug('Attempting to find runtime_morestack function for hooking on...')

    text_seg = get_text_seg()
    if text_seg is None:
        debug('Failed to get text segment')
        return None

    #   Opcodes for "mov     large dword ptr ds:1003h, 0", binary search is faster than text search
    opcodes = 'c7 05 03 10 00 00 00 00 00 00'
    if idaapi.get_inf_structure().is_64bit():
        #   Opcodes for "mov     qword ptr ds:dword_1000+3, 0"
        opcodes = '48 c7 04 25 03 10 00 00 00 00 00 00'

    runtime_ms_end = idaapi.find_binary(text_seg.startEA, text_seg.endEA, opcodes, 0, SEARCH_DOWN)
    if runtime_ms_end == BADADDR:
        debug('Failed to find opcodes associated with runtime_morestack: %s' % opcodes)
        return None

    runtime_ms = idaapi.get_func(runtime_ms_end)
    if runtime_ms is None:
        debug('Failed to get runtime_morestack function from address @ 0x%x' % runtime_ms_end)
        return None

    if idc.MakeNameEx(runtime_ms.startEA, "runtime_morestack", SN_PUBLIC):
        debug('Successfully found runtime_morestack')
    else:
        debug('Failed to rename function @ 0x%x to runtime_morestack' % runtime_ms.startEA)

    return runtime_ms

def traverse_xrefs(func):
    func_created = 0

    if func is None:
        return func_created

    # First
    func_xref = idaapi.get_first_cref_to(func.startEA)
    # Attempt to go through crefs
    while func_xref != BADADDR:
        # See if there is a function already here
        if idaapi.get_func(func_xref) is None:
            # Ensure instruction bit looks like a jump
            func_end = FindCode(func_xref, SEARCH_DOWN)
            if GetMnem(func_end) == "jmp":
                # Ensure we're jumping back "up"
                func_start = GetOperandValue(func_end, 0)
                if func_start < func_xref:
                    if idc.MakeFunction(func_start, func_end):
                        func_created += 1
                    else:
                        # If this fails, we should add it to a list of failed functions
                        # Then create small "wrapper" functions and backtrack through the xrefs of this
                        error('Error trying to create a function @ 0x%x - 0x%x' %(func_start, func_end))
        else:
            xref_func = idaapi.get_func(func_xref)
            # Simple wrapper is often runtime_morestack_noctxt, sometimes it isn't though...
            if is_simple_wrapper(xref_func.startEA):
                debug('Stepping into a simple wrapper')
                func_created += traverse_xrefs(xref_func)
            if idaapi.get_func_name(xref_func.startEA) is not None and 'sub_' not in idaapi.get_func_name(xref_func.startEA):
                debug('Function @0x%x already has a name of %s; skipping...' % (func_xref, idaapi.get_func_name(xref_func.startEA)))
            else:
                debug('Function @ 0x%x already has a name %s' % (xref_func.startEA, idaapi.get_func_name(xref_func.startEA)))

        func_xref = idaapi.get_next_cref_to(func.startEA, func_xref)

    return func_created

def find_func_by_name(name):
    text_seg = get_text_seg()
    if text_seg is None:
        return None

    for addr in Functions(text_seg.startEA, text_seg.endEA):
        if name == idaapi.get_func_name(addr):
            return idaapi.get_func(addr)

    return None

def runtime_init():
    func_created = 0

    if find_func_by_name('runtime_morestack') is not None:
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack'))
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack_noctxt'))
    else:
        runtime_ms = create_runtime_ms()
        func_created = traverse_xrefs(runtime_ms)


    return func_created


#
# Function renaming fuctionality
#

def create_pointer(addr, force_size=None):
    if force_size is not 4 and (idaapi.get_inf_structure().is_64bit() or force_size is 8):
        MakeQword(addr)
        return Qword(addr), 8
    else:
        MakeDword(addr)
        return Dword(addr), 4

STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
def clean_function_name(str):
    # Kill generic 'bad' characters
    str = filter(lambda x: x in string.printable, str)

    for c in STRIP_CHARS:
        str = str.replace(c, '')

    for c in REPLACE_CHARS:
        str = str.replace(c, '_')

    return str

def renamer_init():
    renamed = 0

    gopclntab = get_gopclntab_seg()
    if gopclntab is not None:
        # Skip unimportant header and goto section size
        addr = gopclntab.startEA + 8
        size, addr_size = create_pointer(addr)
        addr += addr_size

        # Unsure if this end is correct
        early_end = addr + (size * addr_size * 2)
        while addr < early_end:
            func_offset, addr_size = create_pointer(addr)
            name_offset, addr_size = create_pointer(addr + addr_size)
            addr += addr_size * 2

            func_name_addr = Dword(name_offset + gopclntab.startEA + addr_size) + gopclntab.startEA
            func_name = GetString(func_name_addr)
            MakeStr(func_name_addr, func_name_addr + len(func_name))
            appended = clean_func_name = clean_function_name(func_name)
            debug('Going to remap function at 0x%x with %s - cleaned up as %s' % (func_offset, func_name, clean_func_name))

            if idaapi.get_func_name(func_offset) is not None:
                if MakeName(func_offset, clean_func_name):
                    renamed += 1
                else:
                    error('clean_func_name error %s' % clean_func_name)

    return renamed


# Function pointers are often used instead of passing a direct address to the
# function -- this function names them based off what they're currently named
# to ease reading
#
# lea     rax, main_GetExternIP_ptr <-- pointer to actual function
# mov     [rsp+1C0h+var_1B8], rax <-- loaded as arg for next function
# call    runtime_newproc <-- function is used inside a new process

def pointer_renamer():
    renamed = 0

    text_seg = get_text_seg()
    if text_seg is None:
        debug('Failed to get text segment')
        return renamed

    for addr in Functions(text_seg.startEA, text_seg.endEA):
        name = GetFunctionName(addr)

        # Look at data xrefs to the function - find the pointer that is located in .rodata
        data_ref = idaapi.get_first_dref_to(addr)
        while data_ref != BADADDR:
            if 'rodata' in idaapi.get_segm_name(data_ref):
                # Only rename things that are currently listed as an offset; eg. off_9120B0
                if 'off_' in GetTrueName(data_ref):
                    if MakeName(data_ref, ('%s_ptr' % name)):
                        renamed += 1
                    else:
                        error('error attempting to name pointer @ 0x%02x for %s' % (data_ref, name))

            data_ref = idaapi.get_next_dref_to(addr, data_ref)

    return renamed

def main():

    # This should be run before the renamer, as it will find and help define more functions
    func_added = runtime_init()
    info('Found and successfully created %d functions!' % func_added)

    # This should prevent the script from locking up due to the auto initalizer
    idaapi.autoWait()

    # Should be run after the function initializer,
    renamed = renamer_init()
    info('Found and successfully renamed %d functions!' % renamed)

    # Attempt to rename all function pointers after we have all the functions and proper function names
    pointers_renamed = pointer_renamer()
    info('Found and successfully renamed %d function pointers!' % pointers_renamed)

    # Attempt to find all string loading idioms
    strings_added = strings_init()
    info('Found and successfully created %d strings!' % strings_added)

if __name__ == "__main__":
    main()
