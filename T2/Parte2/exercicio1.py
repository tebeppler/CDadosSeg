import sys
import pefile

pe = pefile.PE(sys.argv[1])
mem_perm = {
	"0x0": "-",
	"0x1": "s",
	"0x2": "x",
	"0x3": "sx",
	"0x4": "r",
	"0x5": "sr",
	"0x6": "rx",
	"0x8": "w",
	"0xa": "wx",
	"0xc": "rw",
}
plist = {}
for section in pe.sections:
	if hex(section.Characteristics)[:3] in mem_perm:
		perm = str(mem_perm[hex(section.Characteristics)[:3]])
	else:
		perm = hex(section.Characteristics)[:3]
	plist[section.Name.decode("utf-8").rstrip("\0")] = perm
#print(plist)
f = open('T2p2a.txt', 'w') 
for elemento in plist.keys():
	if (plist[elemento] == "x" or plist[elemento] == "sx" or plist[elemento] == "rx" or plist[elemento] == "wx"):
		f.write("Seção: " + elemento + " é executável: " + plist[elemento] + "\n")
	else:
		f.write("Seção: " + elemento + " [não] é executável: " + plist[elemento] + "\n")