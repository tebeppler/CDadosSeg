import xmltodict
import json
import os
import sys

diretorio = sys.argv[1]

f = open('T2p1.txt', 'w')          #abre arquivo de saida para escrita
f.write("===================\n\n")
f.write("Permissões por APK\n\n")
f.write("===================\n\n")


os.chdir(diretorio)

dicPermissoes = {}
dicPermissoes2 = {}

for arquivo in os.listdir(path="."):

    arq = open(arquivo, 'rb')
    doc = xmltodict.parse(arq.read())
    #print(doc)

    name = str(arquivo).split(".")[0]
    nome = name.split("_")[1]
    listaPermissoes = []

    for elemento in doc["manifest"]["uses-permission"]:
        listaPermissoes.append(elemento.get('@android:name').split('.')[-1])        
    dicPermissoes[nome] = listaPermissoes

    for elem in listaPermissoes:
        if elem not in dicPermissoes2:
            dicPermissoes2[elem] = 1
        else:
            dicPermissoes2[elem] += 1

for i in dicPermissoes.keys():
    f.write(i + ":" + str(dicPermissoes[i]) + "\n\n") 

f.write("===================\n\n")
f.write("Permissões únicas por APK\n\n")
f.write("===================\n\n")

dicUnicas = {}
for i in dicPermissoes.keys():
    for j in dicPermissoes[i]:
        if dicPermissoes2[j] == 1:
            f.write(i + ":" + j + "\n\n")

f.write("===================\n\n")
f.write("Permissões comuns das APK\n\n")
f.write("===================\n\n")

for k in dicPermissoes2.keys():
    if dicPermissoes2[k] == 11:
        f.write("['"+ k + "']\n")
