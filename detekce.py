#!/usr/bin/python3
#coding=utf8

# TODO par prikazu, co by se mohly hodit dal
# time nfdump -r nfcapd.tmp 'dst port 22 and (src net 10.0.0.0/8)' -A srcip
# time nfdump -r nfcapd.tmp 'dst port 22 and src ip 10.10.1.181' -s dstip/flows

"""
Popis: Viz. usage()
Autor: Jindrich Vrba
Dne: 30.7.2o21
Posledni uprava: 20.8.2o21
"""

import sys, signal, getpass, getopt, subprocess, csv, os
from datetime import datetime, timedelta

#standardni chovani pri CTRL+C nebo ukonceni roury
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.SIG_DFL)


#jak casto jsou rotovany soubory s NetFlow daty
TIME=10 #[m]

#TODO lokalni sit - zadat vsechny lokalni i verejne rozsahy IP i IPv6
SRC_LNET="(src net 10.0.0.0/8 or src net 198.51.100.0/24 or src net 2001:db8::/32)"
DST_LNET="(dst net 10.0.0.0/8 or dst net 198.51.100.0/24 or dst net 2001:db8::/32)"

#TODO docasne pro testovani
SOUBOR="nfcapd.tmp"


def usage(vystup):
  """ Použití programu
  @param vystup: Kam se bude vypisovat - nejběžněji sys.stderr nebo sys.stdout
  """
  vystup.write("""Detekce útoků z NetFlow dat.

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
  if (netflow_adr_cist!=None):
    prikaz = ["nfdump","-M","/netflow-zakaznicke/%s" % netflow_adr_cist,"-r",SOUBOR,"-o","csv",filtr,"-s","%s/flows" % agreg,"-n0"]
  else:
    prikaz = ["nfdump","-r",SOUBOR,"-o","csv",filtr,"-s","%s/flows" % agreg,"-n0"]
  print("DEBUG spoustim prikaz: %s" % subprocess.list2cmdline(prikaz))
  p1 = subprocess.Popen(prikaz, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout,stderr = p1.communicate()

  if (stderr):
    raise RuntimeError("ERROR Spusteni nfdump prikazu v getStatNFData skoncilo chybou: '%s'!" % (stderr.decode()))

  #DEBUG
  #print(stdout.decode().strip().split('\n'))
  #for radek in stdout.decode().strip().split('\n'):
  #  print(radek)

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


#TODO pokud budeme pouzivat i tuto funkci, upravit nfdump viz getStatNFData
def getNFData(filtr):
  """ Načte NetFlow data dle zadaného filtru.
  @param filtr: Textový řetězec - filtr ve formátu nfdump (rozšířený formát tcpdump)
  @return: Seznam slovníků s daty. Klíčem slovníku jsou sa, da, sp, dp, pr, flg, ipkt a ibyt.
  """
  #TODO nacteni dat pomoci nfdump
  prikaz = ["nfdump","-r",SOUBOR,"-o","csv",filtr]
  p1 = subprocess.Popen(prikaz, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout,stderr = p1.communicate()

  if (stderr):
    raise RuntimeError("ERROR Spusteni nfdump prikazu v getNFData skoncilo chybou: '%s'!" % (stderr.decode()))

  #DEBUG
  #print(stdout.decode().strip().split('\n'))
  #for radek in stdout.decode().strip().split('\n'):
  #  print(radek)

  chcemeKlice=['sa', 'da', 'sp', 'dp', 'pr', 'flg', 'ipkt', 'ibyt']
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
    #statistiky nfdump nas nezajimaji - jsou oddeleny radkem 'Summary'
    if (i==['Summary']):
      break
    #z kazdeho radku udelame slovnik pomoci hlavicky souboru
    tmpD=dict(zip(klice,i))
    #print(tmpD)
    #ale nechame si jen klice, ktere nas zajimaji
    D = dict((k, tmpD[k]) for k in chcemeKlice)
    #print(str(D))
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

  #TODO docasne pro testovani cteni jen konkretniho souboru s daty
  if (len(sys.argv) == 2):
    SOUBOR=sys.argv[1]
    netflow_adr_cist=None
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
    for nfAdresar in os.listdir('/netflow-zakaznicke'):
      if os.path.isdir("/netflow/%s" % nfAdresar):
        if (os.path.isfile("/netflow/%s/%s" % (nfAdresar,SOUBOR))):
          L_adr.append(nfAdresar)
        else:
          sys.stderr.write("WARNING Nenalezen soubor /netflow/%s/%s , nemame udaje z dane sondy!\n" % (nfAdresar,SOUBOR))
    netflow_adr_cist=':'.join(L_adr)
    sys.stderr.write("DEBUG ctu z adresaru: %s\n" % netflow_adr_cist)
    if (netflow_adr_cist==""):
      sys.stderr.write("ERROR Nejsou dostupna zadna data, koncim!\n")
      sys.exit(1)

  #nfData=getStatNFData("dst port 22 and %s" % LNET, "srcip")
  #tmpPamet=sys.getsizeof(nfData)
  #for i in nfData:
  #  tmpPamet+=sys.getsizeof(i)
  #print('DEBUG NetFlow data maji velikost %d bytu' % tmpPamet)
  #print("DEBUG NetFlow data: %s" % nfData)

  #detekce ssh bruteforce z vnitrni site
  nfStat=getStatNFData("dst port 22 and %s" % SRC_LNET, "srcip", mintoku=30)
  print("\nDEBUG NetFlow data (ssh): %s" % nfStat)
  for i in nfStat:
    print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("dst port 22 and %s" % SRC_LNET, "dstip"))
    print("DEBUG %s otevrelo celkem %s spojeni na %d ruznych cilu" % (i['val'],i['fl'],ruznych))

  #detekce telnet bruteforce z vnitrni site
  nfStat=getStatNFData("dst port 23 and %s" % SRC_LNET, "srcip")
  print("\nDEBUG NetFlow data (telnet): %s" % nfStat)
  for i in nfStat:
    print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("dst port 23 and %s" % SRC_LNET, "dstip"))
    print("DEBUG %s otevrelo celkem %s spojeni na %d ruznych cilu" % (i['val'],i['fl'],ruznych))

  #detekce velke mnozstvi oteviranych spojeni - TODO nebudeme resit jinak?
  nfStat=getStatNFData("packets<2 and %s" % SRC_LNET, "srcip", mintoku=10000)
  print("\nDEBUG NetFlow data (mnoho spojeni): %s" % nfStat)

  #detekce dle TCP priznaku Urgent - zatim jen testovaci
  nfStat=getStatNFData("flags U and %s" % SRC_LNET, "srcip", mintoku=100)
  print("\nDEBUG NetFlow data (TCP urgent): %s" % nfStat)

  #detekce velkeho mnozstvi UDP toku - zatim jen testovaci
  nfStat=getStatNFData("proto UDP and %s" % SRC_LNET, "srcip", mintoku=10000)
  print("\nDEBUG NetFlow data (mnoho UDP spojeni): %s" % nfStat)
