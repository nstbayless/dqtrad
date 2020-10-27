import sys
import json
import binascii # for crc32
import re

def hb(a):
    str = hex(a)[2:]
    if (len(str) < 2):
         str = "0" + str
    return str

def HB(a):
    return hb(a).upper()

class Table:
    def __init__(self, f):
        self.table = [None for x in range(0x100)]
        for l in f.readlines():
            if "=" in l:
                c = l.split("=")
                k = int(c[0], 16)
                v = c[1].strip()
                if v == "":
                    v = " "
                self.table[k] = v
    
    def to_string(self, arr):
        s = ""
        for byte in arr:
            t = self.table[int(byte)]
            if t is None:
                s += "\\" + HB(byte)
            else:
                s += t
            
            # insert (meaningless) newline after these
            if byte in [0x80, 0x88, 0xfc, 0xfd, 0xff]:
                s += "\n"
            if byte in [0xfc]:
                s += "\n"
        return s
    
    # recursive text-matching function.
    def to_bytes(self, s):
        a = []
        
        while len(s) > 0:
            match = False
            
            if s[0] == "\n":
                s = s[1:]
                continue
            
            # match up to the next 4 characters.
            for i in reversed(range(1, 5)):
                if len(s) >= i:
                    if s[:i] in self.table:
                        match = True
                        a += [self.table.index(s[:i])]
                        s = s[i:]
                        break
            
            if match:
                continue
            
            # match escape
            if s[0] == "\\" and len(s) >= 3:
                a += [int(s[1:3], 16)]
                s = s[3:]
                continue
        
            raise Exception("cannot match text: \"" + s[:4] + "\"")
        
        return a

def usage():
    print("dqtrad v0.1")
    print()
    print("Usage:")
    print("  python3 dqtrad.py base.nes symbols.json table.tbl [-i hack.txt] [-o hack.txt] [-e modified.nes]")
    print("")
    print("-i: open hack")
    print("-o: save hack")
    print("-e: export to rom")

if "--help" in sys.argv or "-h" in sys.argv:
    usage()
    sys.exit()

basefile=None
symfile=None
outfile=None
infile=None
tablefile=None
exportnes=None

ignore_crc = "-f" in sys.argv

if len(sys.argv) > 2:
    basefile = sys.argv[1]
    symfile = sys.argv[2]
    tablefile = sys.argv[3]

if "-i" in sys.argv[2:-1]:
    infile = sys.argv[sys.argv.index("-i") + 1]

if "-o" in sys.argv[2:-1]:
    outfile = sys.argv[sys.argv.index("-o") + 1]
    
if "-e" in sys.argv[2:-1]:
    exportnes = sys.argv[sys.argv.index("-e") + 1]
    if not exportnes.endswith(".nes"):
        print("Error: exported ROM must have .nes extension.")
        sys.exit(1)

if basefile is None or not basefile.endswith(".nes"):
    usage()
    sys.exit()

if symfile is None or not symfile.endswith(".json"):
    usage()
    sys.exit()

if tablefile is None or not tablefile.endswith(".tbl"):
    usage()
    sys.exit()

# nes binary
bin = None
with open(basefile, "rb") as f:
    bin = bytearray(f.read())

# table
with open(tablefile) as f:
    table = Table(f)

# symbols
with open(symfile) as f:
    symbols = json.load(f)

# check crc.
if not ignore_crc:
    crc32 = binascii.crc32(bin)
    if crc32 != int(symbols["crc32"], 16):
        print("CRC32 mismatch.")
        print("binary: " + HB(crc32) + " / expected: " + symbols["crc32"])
        print("Use -f to ignore.")
        sys.exit()

sections = symbols["sections"]

data = dict()
data["sections"] = dict()
data_sections = data["sections"]

def read_word(addr):
    return int(bin[addr]) + int(bin[addr + 1] * 0x100)    

def write_word(addr, w):
    bin[addr] = w & 0x00ff
    bin[addr + 1] = (w & 0xff00) >> 8

for section in sections:
    schema = sections[section]
    rom_start = int(schema["start"], 16)
    rom_end = int(schema["end"], 16)
    if "table-start" not in schema:
        text = table.to_string(bin[rom_start:rom_end])
        data_sections[section] = text
    else:
        rom_t_start = int(schema["table-start"], 16)
        rom_t_end = int(schema["table-end"], 16)
        bank = int((rom_t_start - 0x10) / 0x4000)
        addresses = [rom_end]
        for i in range(rom_t_start, rom_t_end, 2):
            addresses.append(read_word(i) + 0x10 + 0x4000 * bank - 0x8000)
        addresses = sorted(set(addresses))
        
        data_sections[section] = []
        
        for i in range(rom_t_start, rom_t_end, 2):
            index = (i - rom_t_start) // 2
            if "duplicate" in schema and index == schema["duplicate"]:
                continue
            start_address = read_word(i) + 0x10 + 0x4000 * bank - 0x8000
            end_address = addresses[addresses.index(start_address) + 1]
            if "d_table_idx" in schema and index in schema["d_table_idx"]:
                # special data table
                # skip starting pointer
                data_sections[section].append(
                    bin[start_address + 2:end_address]
                )
            else:
                # text data
                data_sections[section].append(
                    table.to_string(bin[start_address:end_address])
                )

refind = re.compile(r'\"(.*?)\"', re.MULTILINE | re.DOTALL)

# import hack
if infile is not None:
    with open(infile, "r") as f:
        s = f.read()
        for quoted in reversed(list(refind.finditer(s))):
            s = s[:quoted.start()] + quoted.group(0).replace("\n", "") + s[quoted.end():]
        s = s.replace("\\", "\\\\")
        indata = json.loads(s)
        for section in data["sections"]:
            if type(indata["sections"][section]) == type([]):
                for i in range(len(indata["sections"][section])):
                    # don't read this code, please, it's bad. :)
                    if indata["sections"][section][i] == 0:
                        indata["sections"][section][i] = data["sections"][section][i]
            data["sections"][section] = indata["sections"][section]
        
        
# dump hack data to string
def dumps_data(data):
    s = "{\n\"sections\": {"
    for section in data["sections"]:
        s += "\n\n\"" + section + "\":\n\n"
        obj = data["sections"][section]
        if type(obj) == type(""):
            s += "\"" + obj + "\""
        elif type(obj) == type([]):
            s += "["
            s += ",\n\n".join(list(map(lambda x: ("\"" + x + "\"") if type(x) == type("") else "0", obj)))
            s += "]"
        s += ","
    s = s[:-1]
    s += "\n\n}}"
    return s

if exportnes is not None:
    # commit data to bin
    for section in sections:
        obj = data_sections[section]
        schema = sections[section]
        rom_start = int(schema["start"], 16)
        rom_end = int(schema["end"], 16)
        if "table-start" not in schema:
            insert = table.to_bytes(obj)
            if len(insert) > rom_end - rom_start:
                raise Exception("section \"" + section + "\" space exceeded by " + str(len(insert) - (rom_end - rom_start)))
            else:
                for i in range(len(insert)):
                    bin[rom_start + i] = insert[i]
        else:
            rom_t_start = int(schema["table-start"], 16)
            rom_t_end = int(schema["table-end"], 16)
            bank = int((rom_t_start - 0x10) / 0x4000)
            table_i = -1
            for t in obj:
                table_i += 1
                
                if "duplicate" in schema and table_i == schema["duplicate"]:
                    write_word(rom_t_start + 2 * table_i, read_word(rom_t_start + 2 * table_i - 2))
                    continue
                
                # adjust metatable to point here.
                write_word(rom_t_start + 2 * table_i, rom_start - 0x10 + 0x8000 - 0x4000 * bank)
                
                if type(t) == type(""):
                    insert = table.to_bytes(t)
                    if len(insert) > rom_end - rom_start:
                        raise Exception("section \"" + section + "\" space exceeded in table no. " + str(table_i) + " by " + str(len(insert) - (rom_end - rom_start)))
                    else:
                        for i in range(len(insert)):
                            bin[rom_start + i] = insert[i]
                    rom_start += len(insert)
                else:
                    # pointer to start of table
                    # (why dq would be coded this way is beyond me)
                    write_word(rom_start, rom_start + 2 - 0x10 + 0x8000 - 0x4000 * bank)
                    rom_start += 2
                    
                    insert = t
                    for i in range(len(insert)):
                        bin[rom_start + i] = insert[i]
                    rom_start += len(insert)
                    
    
    # write binary
    with open(exportnes, "wb") as f:
        f.write(bin)

if outfile is None and exportnes is None:
    print(dumps_data(data))
elif outfile is not None:
    with open(outfile, "w") as f:
        f.write(dumps_data(data))