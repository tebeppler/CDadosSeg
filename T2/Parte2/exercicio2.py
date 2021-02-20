import sys
import pefile

pe = pefile.PE(sys.argv[1])
pe2 = pefile.PE(sys.argv[2])

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

plist1 = {}
plist2 = {}
for section in pe.sections:
	if hex(section.Characteristics)[:3] in mem_perm:
		perm = str(mem_perm[hex(section.Characteristics)[:3]])
	else:
		perm = hex(section.Characteristics)[:3]
	plist1[section.Name.decode("utf-8").rstrip("\0")] = perm

for section in pe2.sections:
	if hex(section.Characteristics)[:3] in mem_perm:
		perm = str(mem_perm[hex(section.Characteristics)[:3]])
	else:
		perm = hex(section.Characteristics)[:3]
	plist2[section.Name.decode("utf-8").rstrip("\0")] = perm

f = open('T2p2b.txt', 'w') 	

for i in plist1.keys():
	for j in plist2.keys():
		if (plist1[i] == "x" or plist1[i] == "sx" or plist1[i] == "rx" or plist1[i] == "wx"):
			executavel1 = 1
		else:
			executavel1 = 0
		if (plist2[j] == "x" or plist2[j] == "sx" or plist2[j] == "rx" or plist2[j] == "wx"):
			executavel2 = 1
		else:
			executavel2 = 0	
		if i == j:
			if plist1[i] == plist2[j]:
				if executavel1 == 1 and executavel2 == 1:
					f.write("Binário " + sys.argv[1] + " e " + sys.argv[2] + " contém a seção " + i + " executável: " + plist1[i]+ "\n")
				else:
					f.write("Binário " + sys.argv[1] + " e " + sys.argv[2] + " contém a seção " + i + " [não] executável: " + plist1[i]+ "\n")
			else:
				if executavel1 == 1:
					f.write("Apenas binário " + sys.argv[1] + " contém a seção " + i + " executável: " + plist1[i]+ "\n")
				else: 
					if executavel2 == 2:
						f.write("Apenas binário " + sys.argv[2] + " contém a seção " + j + " executável: " + plist1[j] + "\n")
					else:
						f.write("Binário " + sys.argv[1] + " contém a seção " + i + " [não] executável: " + plist1[i] + "\ne " + sys.argv[2] + " contém a seção " + j + " [não] executável: " + plist1[j]+ "\n")