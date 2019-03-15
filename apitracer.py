import sys, struct
import pefile
from pydbg import *
from pydbg.defines import *
from collections import defaultdict

#code borrowed from https://securityxploded.com/api-call-tracing-with-pefile-pydbg-and-idapython.php


def addr_handler(dbg):
    global func_name
    ret_addr = dbg.context.Eax
    if ret_addr:
        dict[ret_addr] = func_name
        dbg.bp_set(ret_addr, handler=generic)
    return DBG_CONTINUE


def generic(dbg):
    global func_name
    eip = dbg.context.Eip
    esp = dbg.context.Esp
    paddr = dbg.read_process_memory(esp, 4)
    addr = struct.unpack("L", paddr)[0]
    addr = int(addr)

    if addr < 70000000:
        addre = "0x%.8x" % addr
        #results_dict[dict[eip]].update({'addr' :addre})
        #results_dict.setdefault(dict[eip], {}).setdefault('addr', "")
        results_dict.setdefault(dict[eip], {}).setdefault('call_count', 0)
        if results_dict.has_key(dict[eip]):
            #results_dict[dict[eip]]['addr'] += ',%s' % (addre)
            results_dict[dict[eip]]['call_count'] += 1
            
    if dict[eip] == "KERNEL32!GetProcAddress" or dict[eip] == "GetProcAddress":
        try:
            esp = dbg.context.esp
            addr = esp + 0x08
            size = 50
            pstring = dbg.read_process_memory(addr, 4)
            pstring = struct.unpack("L", pstring)[0]
            pstring = int(pstring)
            if pstring > 500:
                data = dbg.read_process_memory(pstring, size)
                func_name = dbg.get_ascii_string(data)
            else:
                func_name = "ordinal entry"
            paddr = dbg.read_process_memory(esp, 4)
            addr = struct.unpack("L", addr)[0]
            addr = int(addr)
            dbg.bp_set(addr, handler=addr_handler)
        except Exception as ex:
            pass

    return DBG_CONTINUE


def entryhandler(dbg):
    getaddr = dbg.func_resolve("kernel32.dll", "GetProcAddress")
    dict[getaddr] = "kernel32!GetProcAddress"
    dbg.bp_set(getaddr, handler=generic)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dllName = entry.dll
        for imp in entry.imports:
            api = imp.name
            address = dbg.func_resolve(dllName, api)
            if address:
                try:
                    dllName = dllName.split(".")[0]

                    dll_func = "{}!{}".format(dllName, api)
                    dict[address] = dll_func
                    dbg.bp_set(address, handler=generic)
                except Exception as ex:
                    pass
    return DBG_CONTINUE


def main():
    global pe, DllName, func_name, fpp
    global dict
    global results_dict
    results_dict = defaultdict(dict)
    dict = {}
    file = sys.argv[1]
    pe = pefile.PE(file)
    dbg = pydbg()
    dbg.load(file)
    entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    dbg.bp_set(entrypoint, handler=entryhandler)
    dbg.run()

    for api, count in results_dict.items():
        print("called funct: {} --------> times called: {}").format(api,count['call_count'])

if __name__ == '__main__':
    main()
