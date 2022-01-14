#!/usr/bin/python3
#coding=utf8

"""
Popis: Viz. usage()
Autor: Jindrich Vrba
Dne: 15.10.2021
Posledni uprava: 14.1.2022
"""

import sys, signal, getpass, getopt, subprocess, csv, os
from datetime import datetime, timedelta

#standardni chovani pri CTRL+C nebo ukonceni roury
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.SIG_DFL)

#jak casto jsou rotovany soubory s NetFlow daty
TIME=10 #[m]

#lokalni sit - zadat verejne rozsahy IPv4 i IPv6; neverejne rozsahy zde nema smysl zadavat
DST_LNET="(dst net 198.51.100.0/24 or dst net 2001:db8::/32)"


def usage(vystup):
  """ Použití programu
  @param vystup: Kam se bude vypisovat - nejběžněji sys.stderr nebo sys.stdout
  """
  vystup.write("""Detekce útoků z internetu do vnitřní sítě dle NetFlow dat.

  V části mojí diplomové práce se zabývám detekcí síťových útoků.
  Tento skript má za úkol hledat různé známé vzory chování případně
  neobvyklou komunikaci.

Pouziti:
%s [-h|--help]
  \n""" % (sys.argv[0]))


def getStatNFData(filtr, agreg, mintoku=None):
  """ Načte statistiky z NetFlow dat dle zadaného filtru.
  @param filtr: Textový řetězec - filtr ve formátu nfdump (rozšířený formát tcpdump)
  @param agreg: Agregační klíč, podle kterého seskupovat záznamy
  @param mintoku: Získat jen záznamy s alespoň takovýmto počtem toků.
  @return: Seznam slovníků s daty. Klíčem slovníku je val a fl. Val je dle agregační funkce, fl je počet toků.
  """
  #TODO nacteni dat pomoci nfdump
  #if (netflow_adr_cist!=None):
  #  prikaz = ["nfdump","-M","/netflow-konektivity/%s" % netflow_adr_cist,"-r",SOUBOR,"-o","csv",filtr,"-s","%s/flows" % agreg,"-n0"]
  #else:
  #  prikaz = ["nfdump","-r",SOUBOR,"-o","csv",filtr,"-s","%s/flows" % agreg,"-n0"]
  prikaz = ["nfdump","-M","/netflow-konektivity/%s" % netflow_adr_cist,"-r",SOUBOR,"-o","csv",filtr,"-s","%s/flows" % agreg,"-n0"]
  #print("DEBUG spoustim prikaz: %s" % subprocess.list2cmdline(prikaz))
  p1 = subprocess.Popen(prikaz, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout,stderr = p1.communicate()

  if (stderr):
    raise RuntimeError("ERROR Spusteni nfdump prikazu v getStatNFData skoncilo chybou: '%s'!" % (stderr.decode()))

  chcemeKlice=['val', 'fl']
  nfData=[]
  tmpD=D=None
  reader=csv.reader(stdout.decode().strip().split('\n'))
  klice=next(reader)
  #print("DEBUG klice: %s" % klice)
  #kontrola, jestli jsou vsechny klice dostupne
  for k in chcemeKlice:
    if k not in klice:
      raise RuntimeError("ERROR V NetFlow datech nenachazim zaznam s klicem '%s'!" % (k))
  for i in reader:
    #print("DEBUG '%s'" % i)
    #statistiky nfdump nas nezajimaji - jsou oddeleny prazdnym radkem
    if (i==[]):
      break
    #z kazdeho radku udelame slovnik pomoci hlavicky souboru
    tmpD=dict(zip(klice,i))
    #print(tmpD)
    #ale nechame si jen klice, ktere nas zajimaji
    D = dict((k, tmpD[k]) for k in chcemeKlice)
    #print(str(D))
    #filtrace podle mintoku, pokud je zapnuto
    if (mintoku!=None and int(D['fl'])<mintoku):
      break
    nfData.append(D)

  return nfData


if __name__ == "__main__":
  if (getpass.getuser() != "statistiky"):
    sys.stderr.write("Tento skript smi pouzivat jen uzivatel statistiky.\n")
    sys.exit(1)

  try:
    opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
  except getopt.GetoptError as err:
    sys.stderr.write("%s\n" % str(err))
    usage(sys.stderr)
    sys.exit(1)
  for o in opts:
    if o[0] in ("-h", "--help"):
      usage(sys.stdout)
      sys.exit()

  #if (len(sys.argv) != 1):
  #  sys.stderr.write("Spatny pocet parametru.\n")
  #  usage(sys.stderr)
  #  sys.exit(1)

  #pro cteni konkretniho data dle parametru - format 2022-01-06/nfcapd.202201061540
  if (len(sys.argv) == 2):
    SOUBOR=sys.argv[1]
  #jinak cteni aktualnich souboru s daty ze vsech sond
  else:
    #nazev souboru je dle zacatku zaznamu, tedy TIME minut zpetne
    cas=datetime.now()-timedelta(minutes=TIME)
    #casovy udaj, pro ktery nas zajimaji statistiky - napr 202108261720 pro 26.8.2021 17:20
    soubor_cast1=cas.strftime("%Y%m%d%H")
    #oriznout celociselnym delenim na cele desitky
    soubor_cast2=int(int(cas.strftime("%M"))/TIME)*TIME
    #podadresar ve formatu 2021-08-26
    podadresar="%s" % cas.strftime("%Y-%m-%d")
    #format 2021-08-26/nfcapd.202108261720
    SOUBOR="%s/nfcapd.%s%02d" % (podadresar,soubor_cast1,soubor_cast2)
    print("DEBUG sbiram statistiky ze souboru %s\n" % SOUBOR)

  L_adr=[]
  for nfAdresar in os.listdir('/netflow-konektivity'):
    if os.path.isdir("/netflow-konektivity/%s" % nfAdresar):
      if (os.path.isfile("/netflow-konektivity/%s/%s" % (nfAdresar,SOUBOR))):
        L_adr.append(nfAdresar)
      else:
        sys.stderr.write("WARNING Nenalezen soubor /netflow-konektivity/%s/%s , nemame udaje z dane sondy!\n" % (nfAdresar,SOUBOR))
  netflow_adr_cist=':'.join(L_adr)
  sys.stderr.write("DEBUG ctu z adresaru: %s\n" % netflow_adr_cist)
  if (netflow_adr_cist==""):
    sys.stderr.write("ERROR Nejsou dostupna zadna data, koncim!\n")
    sys.exit(1)

  #TODO zkusebne neco vycist
  #nfData=getStatNFData("dst port 22 and %s" % DST_LNET, "srcip")
  #tmpPamet=sys.getsizeof(nfData)
  #for i in nfData:
  #  tmpPamet+=sys.getsizeof(i)
  #print('DEBUG NetFlow data maji velikost %d bytu' % tmpPamet)
  #print("DEBUG NetFlow data: %s" % nfData)

  #TODO SYN scan
  nfStat=getStatNFData("proto TCP and flags S and not flags UPF and packets < 4 and %s" % DST_LNET, "srcip", mintoku=1000)
  print("\nDEBUG NetFlow data (SYN scan): %s\n" % nfStat)
  #projdeme vsechny takove IP z netu
  for i in nfStat:
    print("DEBUG ip %s: flows %s" % (i['val'],i['fl']))
    #kontrolne, kolik maji celkem spojeni
    debug=getStatNFData("%s and src ip %s" % (DST_LNET,i['val']), "srcip")
    if (debug!=[]):
      tmp_all=int(debug[0]['fl'])
    else:
      tmp_all=0
    print("DEBUG all: flows %d" % (tmp_all))
    #kontrolne, kolik maji RST TCP spojeni
    debug=getStatNFData("proto TCP and flags R and not flags UAPSF and %s and src ip %s" % (DST_LNET,i['val']), "srcip")
    if (debug!=[]):
      tmp_rst=int(debug[0]['fl'])
    else:
      tmp_rst=0
    print("DEBUG TCP RST: flows %d" % (tmp_rst))
    print()

  #TODO detekce velke mnozstvi oteviranych spojeni bez odezvy
  nfStat=getStatNFData("packets<2 and not src port in [53, 80, 443, 5228] and %s" % DST_LNET, "srcip", mintoku=1000)
  print("\nDEBUG NetFlow data (mnoho spojeni jen s 1 paketem): %s\n" % nfStat)
  #projdeme vsechny takove IP z netu, ktere mely navazano vice nez X spojeni
  for i in nfStat:
    print("DEBUG ip %s: flows %s" % (i['val'],i['fl']))
    nfStat_ip=getStatNFData("packets<2 and not src port in [53, 80, 443, 5228] and %s and src ip %s" % (DST_LNET,i['val']), "dstport", mintoku=100)
    print("DEBUG %s : %s" % (i['val'],nfStat_ip))
    #projit porty, na ktere bylo navazano vic nez Y spojeni
    for j in nfStat_ip:
      print("DEBUG ip %s dst port %s : flows %s" % (i['val'],j['val'],j['fl']))
    print()
