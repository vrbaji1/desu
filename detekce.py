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

import sys, signal, getpass, getopt, subprocess, csv

#standardni chovani pri CTRL+C nebo ukonceni roury
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.SIG_DFL)


def usage(vystup):
  """ Použití programu
  @param vystup: Kam se bude vypisovat - nejbezneji sys.stderr nebo sys.stdout
  """
  vystup.write("""Detekce útoků z NetFlow dat.

  V části mojí diplomové práce se zabývám detekcí síťových útoků.
  Tento skript má za úkol hledat různé známé vzory chování případně
  neobvyklou komunikaci.

Pouziti:
%s [-h|--help]
  \n""" % (sys.argv[0]))


def getStatNFData():
  """ Načte statistiky z NetFlow dat.
  """
  #TODO nacteni dat pomoci nfdump
  prikaz = ["nfdump","-r","nfcapd.tmp","-o","csv","dst port 22","-s","srcip/flows","-n","0"]
  p1 = subprocess.Popen(prikaz, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout,stderr = p1.communicate()

  #TODO
  print("DEBUG stderr: %s" % stderr.decode())
  print(stdout.decode().strip().split('\n'))
  for radek in stdout.decode().strip().split('\n'):
    print(radek)

  chcemeKlice=['val', 'fl']
  nfData=[]
  tmpD=D=None
  reader=csv.reader(stdout.decode().strip().split('\n'))
  keys=next(reader)
  #print("DEBUG klice: %s" % keys)
  for k in chcemeKlice:
    if k not in keys:
      raise RuntimeError("ERROR V NetFlow datech nenachazim zaznam s klicem '%s'!" % (k))
  for i in reader:
    print("DEBUG '%s'" % i)
    #statistiky nfdump nas nezajimaji
    if (i==[]):
      break
    #z kazdeho radku udelame slovnik pomoci hlavicky souboru
    tmpD=dict(zip(keys,i))
    #print(tmpD)
    #ale nechame si jen klice, ktere nas zajimaji
    D = dict((k, tmpD[k]) for k in chcemeKlice)
    #print(str(D))
    nfData.append(D)

  return nfData


def getNFData():
  """ Načte NetFlow data.
  """
  #TODO nacteni dat pomoci nfdump
  prikaz = ["nfdump","-r","nfcapd.tmp","-o","csv","port 22"]
  p1 = subprocess.Popen(prikaz, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout,stderr = p1.communicate()

  #TODO
  #print("DEBUG stderr: %s" % stderr.decode())
  #print(stdout.decode().strip().split('\n'))
  #for radek in stdout.decode().strip().split('\n'):
  #  print(radek)

  chcemeKlice=['sa', 'da', 'sp', 'dp', 'pr', 'flg', 'ipkt', 'ibyt']
  nfData=[]
  tmpD=D=None
  reader=csv.reader(stdout.decode().strip().split('\n'))
  keys=next(reader)
  #print("DEBUG klice: %s" % keys)
  for k in chcemeKlice:
    if k not in keys:
      raise RuntimeError("ERROR V NetFlow datech nenachazim zaznam s klicem '%s'!" % (k))
  for i in reader:
    #print("DEBUG '%s'" % i)
    #statistiky nfdump nas nezajimaji
    if (i==['Summary']):
      break
    #z kazdeho radku udelame slovnik pomoci hlavicky souboru
    tmpD=dict(zip(keys,i))
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

  if (len(sys.argv) != 1):
    sys.stderr.write("Spatny pocet parametru.\n")
    usage(sys.stderr)
    sys.exit(1)

  nfData=getStatNFData()
  tmpPamet=sys.getsizeof(nfData)
  for i in nfData:
    tmpPamet+=sys.getsizeof(i)
  print('DEBUG NetFlow data maji velikost %d bytu' % tmpPamet)
  print("DEBUG NetFlow data: %s" % nfData)

