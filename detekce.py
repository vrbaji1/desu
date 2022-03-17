#!/usr/bin/python3
#coding=utf8

"""
Popis: Viz. usage()
Autor: Jindrich Vrba
Dne: 30.7.2o21
Posledni uprava: 17.3.2o22
"""

import sys, signal, getpass, getopt, subprocess, csv, os, ipaddress
from datetime import datetime, timedelta

#standardni chovani pri CTRL+C nebo ukonceni roury
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.SIG_DFL)


#jak casto jsou rotovany soubory s NetFlow daty
TIME=10 #[m]

#verejne i neverejne rozsahy IPv4 i IPv6 poskytovatele
SRC_ISP="(src net 10.0.0.0/8 or src net 198.51.100.0/24 or src net 2001:db8::/32)"


def usage(vystup):
  """ Použití programu
  @param vystup: Kam se bude vypisovat - nejběžněji sys.stderr nebo sys.stdout
  """
  vystup.write("""Detekce útoků z vnitřní sítě do internetu dle NetFlow dat.

  V části mojí diplomové práce se zabývám detekcí síťových útoků.
  Tento skript má za úkol hledat různé typy útoků a neobvyklou komunikaci.

Pouziti:
%s [-h|--help]
  \n""" % (sys.argv[0]))


def getStatNFData(filtr, agreg, poradi='flows', minimum=None):
  """ Načte statistiky z NetFlow dat dle zadaného filtru.
  @param filtr: Textový řetězec - filtr ve formátu nfdump (rozšířený formát tcpdump)
  @param agreg: Agregační klíč, podle kterého seskupovat záznamy
  @param poradi: Řazení záznamů - flows / bytes.
  @param minimum: Získat jen záznamy s alespoň takovýmto počtem zadaného dle parametru pořadí.
  @return: Seznam slovníků s daty. Klíčem slovníku je val a fl / byt, dle zadaneho poradi. Val je dle agregační funkce, fl je počet toků, byt je počet Bytů.
  """
  #dalsi poradi mozno pridat dle manualu nfdump parametr -s a klic dle parametru -o csv
  if (poradi=='flows'):
    klic='fl'
  elif (poradi=='bytes'):
    klic='byt'
  else:
    raise RuntimeError("ERROR Nezname poradi: '%s'!" % (poradi))

  #nacteni dat pomoci nfdump
  prikaz = ["nfdump","-M","/netflow-zakaznicke/%s" % netflow_adr_cist,"-r",SOUBOR,"-o","csv",filtr,"-s","%s/%s" % (agreg, poradi),"-n0"]
  #print("DEBUG spoustim prikaz: %s" % subprocess.list2cmdline(prikaz))
  p1 = subprocess.Popen(prikaz, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout,stderr = p1.communicate()

  if (stderr):
    raise RuntimeError("ERROR Spusteni nfdump prikazu v getStatNFData skoncilo chybou: '%s'!" % (stderr.decode()))

  chcemeKlice=['val', klic]
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
    #filtrace podle parametru minimum, pokud je zapnuto
    if (minimum!=None and int(D[klic])<minimum):
      break
    nfData.append(D)

  return nfData


#TODO pokud budeme pouzivat i tuto funkci, upravit nfdump viz getStatNFData
def getNFData(filtr):
  """ Načte NetFlow data dle zadaného filtru.
  @param filtr: Textový řetězec - filtr ve formátu nfdump (rozšířený formát tcpdump)
  @return: Seznam slovníků s daty. Klíčem slovníku jsou sa, da, sp, dp, pr, flg, ipkt a byt.
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

  chcemeKlice=['sa', 'da', 'sp', 'dp', 'pr', 'flg', 'ipkt', 'byt']
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

  if (len(sys.argv) > 2):
    sys.stderr.write("Spatny pocet parametru.\n")
    usage(sys.stderr)
    sys.exit(1)

  #pro cteni konkretniho data dle parametru - format 2022-02-24/nfcapd.202202240400
  if (len(sys.argv) == 2):
    SOUBOR=sys.argv[1]
  #jinak cteni aktualnich souboru s daty ze vsech sond
  else:
    #nazev souboru je dle zacatku zaznamu, tedy TIME minut zpetne
    cas=datetime.now()-timedelta(minutes=TIME)
    #casovy udaj, pro ktery nas zajimaji statistiky - napr 202108261720 pro 26.8.2021 17:20
    soubor_cast1=cas.strftime("%Y%m%d%H")
    #oriznout celociselnym delenim na cele hodnoty dle TIME
    soubor_cast2=int(int(cas.strftime("%M"))/TIME)*TIME
    #podadresar ve formatu 2021-08-26
    podadresar="%s" % cas.strftime("%Y-%m-%d")
    #format 2021-08-26/nfcapd.202108261720
    SOUBOR="%s/nfcapd.%s%02d" % (podadresar,soubor_cast1,soubor_cast2)

  print("DEBUG sbiram statistiky ze souboru %s\n" % SOUBOR)

  L_adr=[]
  for nfAdresar in os.listdir('/netflow-zakaznicke'):
    if os.path.isdir("/netflow-zakaznicke/%s" % nfAdresar):
      if (os.path.isfile("/netflow-zakaznicke/%s/%s" % (nfAdresar,SOUBOR))):
        L_adr.append(nfAdresar)
      else:
        sys.stderr.write("WARNING Nenalezen soubor /netflow-zakaznicke/%s/%s , nemame udaje z dane sondy!\n" % (nfAdresar,SOUBOR))
  netflow_adr_cist=':'.join(L_adr)
  sys.stdout.write("DEBUG ctu z adresaru: %s\n\n" % netflow_adr_cist)
  if (netflow_adr_cist==""):
    sys.stderr.write("ERROR Nejsou dostupna zadna data, koncim!\n")
    sys.exit(1)

  #nfData=getStatNFData("dst port 22 and %s" % LNET, "srcip")
  #tmpPamet=sys.getsizeof(nfData)
  #for i in nfData:
  #  tmpPamet+=sys.getsizeof(i)
  #print('DEBUG NetFlow data maji velikost %d bytu' % tmpPamet)
  #print("DEBUG NetFlow data: %s" % nfData)

  #detekce skenovani SSH - hledame neuspesna spojeni - vice nez 1/10s
  nfStat=getStatNFData("proto TCP and dst port 22 and flags S and not flags A and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (ssh SYN): %s" % nfStat)
  for i in nfStat:
    #print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("proto TCP and dst port 22 and flags S and not flags A and src ip %s" % (i['val']), "dstip"))
    print("INFO proverte rucne: IP %s celkem %s neuspesnych SSH spojeni na %d ruznych cilu" % (i['val'],i['fl'],ruznych))

  #detekce skenovani telnet - hledame neuspesna spojeni - vice nez 1/10s
  nfStat=getStatNFData("proto TCP and dst port 23 and flags S and not flags A and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (telnet SYN): %s" % nfStat)
  for i in nfStat:
    #print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("proto TCP and dst port 23 and flags S and not flags A and src ip %s" % (i['val']), "dstip"))
    print("INFO proverte rucne: IP %s celkem %s neuspesnych telnet spojeni na %d ruznych cilu" % (i['val'],i['fl'],ruznych))

  #detekce skenovani mail sluzeb - hledame neuspesna spojeni - vice nez 1/10s
  nfStat=getStatNFData("proto TCP and dst port in [25,465,587] and flags S and not flags A and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (mail SYN): %s" % nfStat)
  for i in nfStat:
    #print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("proto TCP and dst port in [25,465,587] and flags S and not flags A and src ip %s" % (i['val']), "dstip"))
    print("INFO proverte rucne: IP %s celkem %s neuspesnych spojeni na mail sluzby na %d ruznych cilu" % (i['val'],i['fl'],ruznych))

  #detekce skenovani MikroTik sluzeb - hledame neuspesna spojeni - vice nez 1/10s: 8291 - Winbox, 8728 - API, 8729 - API-SSL
  nfStat=getStatNFData("proto TCP and dst port in [8291,8728,8729] and flags S and not flags A and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (MikroTik sluzby SYN): %s" % nfStat)
  for i in nfStat:
    #print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("proto TCP and dst port in [8291,8728,8729] and flags S and not flags A and src ip %s" % (i['val']), "dstip"))
    print("INFO proverte rucne: IP %s celkem %s neuspesnych spojeni na MikroTik sluzby na %d ruznych cilu" % (i['val'],i['fl'],ruznych))

  #detekce skenovani SMB - hledame neuspesna spojeni - vice nez 1/10s
  nfStat=getStatNFData("proto TCP and dst port 445 and flags S and not flags A and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (SMB SYN): %s" % nfStat)
  for i in nfStat:
    #print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("proto TCP and dst port 445 and flags S and not flags A and src ip %s" % (i['val']), "dstip"))
    print("INFO proverte rucne: IP %s celkem %s neuspesnych SMB spojeni na %d ruznych cilu" % (i['val'],i['fl'],ruznych))

  #detekce DNS server: UDP 53 - skutecne chteji provozovat DNS server? - lze pouzit na amplification attack
  nfStat=getStatNFData("src port 53 and proto udp and %s" % SRC_ISP, "srcip", minimum=60*TIME/2)
  print("\nDEBUG NetFlow data (UDP DNS): %s" % nfStat)

  #detekce NTP server: UDP 123 - skutecne chteji provozovat NTP server? - lze pouzit na amplification attack
  nfStat=getStatNFData("src port 123 and proto udp and %s" % SRC_ISP, "srcip", minimum=60*TIME/6)
  print("\nDEBUG NetFlow data (NTP): %s" % nfStat)

  #detekce WSD UDP - vyuzivano pro DDoS - je urceno jen pro lokalni sit - ma reagovat na multicast adrese 239.255.255.250 a ne na unicast
  #vice viz. https://www.akamai.com/blog/security/new-ddos-vector-observed-in-the-wild-wsd-attacks-hitting-35gbps
  nfStat=getStatNFData("proto UDP and src port 3702 and %s" % SRC_ISP, "srcip", minimum=60*TIME/60)
  print("\nDEBUG NetFlow data (WSD): %s" % nfStat)

  #detekce velke mnozstvi oteviranych spojeni jen s 1 paketem - vice nez 50/s
  nfStat=getStatNFData("packets<2 and %s" % SRC_ISP, "srcip", minimum=60*TIME*50)
  print("\nDEBUG NetFlow data (mnoho spojeni jen s 1 paketem): %s" % nfStat)

  #detekce dle TCP priznaku Urgent - zatim jen testovaci
  nfStat=getStatNFData("flags U and %s" % SRC_ISP, "srcip", minimum=60*TIME)
  print("\nDEBUG NetFlow data (TCP urgent): %s" % nfStat)

  #detekce velkeho mnozstvi UDP toku - vice nez 100/s
  nfStat=getStatNFData("proto UDP and %s" % SRC_ISP, "srcip", minimum=60*TIME*100)
  print("\nDEBUG NetFlow data (mnoho UDP spojeni): %s" % nfStat)

  #Null scan - vice nez 1/10s
  nfStat=getStatNFData("proto TCP and not flags ASRUPF and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (Null scan): %s\n" % nfStat)

  #FIN scan - vice nez 1/10s
  nfStat=getStatNFData("proto TCP and flags F and not flags ASRPU and packets<2 and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (FIN scan): %s\n" % nfStat)

  #Xmas Tree scan - vize nez 1/10s
  nfStat=getStatNFData("proto TCP and flags UPF and not flags ASR and packets < 2 and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (Xmas Tree scan): %s\n" % nfStat)

  #TCP SYN scan - vice nez 1/s nedokoncenych pozadavku na spojeni
  nfStat=getStatNFData("proto TCP and flags S and not flags A and %s" % SRC_ISP, "srcip", minimum=60*TIME)
  print("\nDEBUG NetFlow data (SYN scan): %s\n" % nfStat)
  #projdeme vsechny takove IP vnitrni site
  for i in nfStat:
    #print("DEBUG ip %s: flows %s" % (i['val'],i['fl']))
    print("INFO proverte rucne: IP %s - mozny SYN scan / attack - %s nedokoncenych pozadavku na spojeni" % (i['val'],i['fl']))

  #UDP skenovani / utok - obecny pristup - snazime se rozpoznat IP adresy, ktere skenuji nebo utoci
  nfStat=getStatNFData("proto UDP and packets<2 and %s" % SRC_ISP, "srcip", minimum=60*TIME)
  #print("\nDEBUG NetFlow data (UDP scan / attack): %s\n" % nfStat)
  print("\nDEBUG NetFlow data (UDP scan / attack):\n")
  #Kvuli optimalizaci ziskame i UDP komunikaci obracenym smerem, jiz bez omezeni na 1 paket, optimalni je cca do 50% toku puvodniho dotazu. Kde nebude vyctena hodnota, vycte se zvlast.
  #musime zvlast IPv4 a IPv6, kvuli NAT u IPv4
  nfStat_pro_optimalizaci= getStatNFData("inet  and proto UDP", "ndstip", minimum=60*TIME*0.5)
  nfStat_pro_optimalizaci+=getStatNFData("inet6 and proto UDP", "dstip",  minimum=60*TIME*0.5)
  #print("\nDEBUG optimalizace: %s\n" % nfStat_pro_optimalizaci)
  #projdeme vsechny podezrele IP z netu
  for i in nfStat:
    #print("DEBUG ip %s: flows %s" % (i['val'],i['fl']))

    #vycist UDP smerem z internetu na tuto IP naseho zakaznika
    udp_back=0
    #nejdriv se snazime najit v jiz vyctenych datech
    for j in nfStat_pro_optimalizaci:
      if (j['val']==i['val']):
        udp_back=int(j['fl'])
        #print("DEBUG nalezeno: %d" % udp_back)
        break
    #pokud hodnoty nemame, vycteme
    if (udp_back==0):
      #print("DEBUG nutno vycist hodnotu obracenym smerem")
      #IPv4 vs IPv6 vycteme jinak - IPv4 z NAT IP
      if isinstance(ipaddress.ip_network(i['val']), ipaddress.IPv4Network):
        debug=getStatNFData("proto udp and dst nip %s" % (i['val']), "ndstip")
      else:
        debug=getStatNFData("proto udp and dst ip %s" % (i['val']), "dstip")
      if (debug!=[]):
        #print(debug)
        udp_back=int(debug[0]['fl'])
      else:
        udp_back=0
    #Trovnou vyradit pripady, kde je reakce na vice nez 50% komunikace
    if (udp_back >= int(0.5*int(i['fl']))):
      #print("DEBUG Mame alespon 50% UDP toku na tuto IP do internetu, jako smerem od ni s 1 paketem, to neni potreba dale resit.\n")
      continue

    #kontrolni vypis, uz jen podezrelych
    #print("DEBUG ip %s: flows %s" % (i['val'],i['fl']))
    #print("DEBUG UDP obracenym smerem: flows %d" % (udp_back))

    #vycist ICMP Destination Unreachable smerem na tento cil - pokud je jen SNAT, nikdy nic nenalezne, skonci to na verejne IP
    if isinstance(ipaddress.ip_network(i['val']), ipaddress.IPv4Network):
      debug=getStatNFData("dst nip %s and icmp-type 3" % (i['val']), "ndstip")
    else:
      debug=getStatNFData("dst  ip %s and icmp-type 1" % (i['val']), "dstip")
    if (debug!=[]):
      #print(debug)
      udp_icmp_unreach=int(debug[0]['fl'])
    else:
      udp_icmp_unreach=0
    #print("- DEBUG ICMP unreachable na tento cil: %d" % (udp_icmp_unreach))

    #vycist pocet ruznych protistran
    if isinstance(ipaddress.ip_network(i['val']), ipaddress.IPv4Network):
      debug=getStatNFData("proto udp and src ip %s" % (i['val']), "ndstip")
    else:
      debug=getStatNFData("proto udp and src ip %s" % (i['val']), "dstip")
    if (debug!=[]):
      #print(debug)
      udp_different=len(debug)
    else:
      udp_different=0
    #print("DEBUG UDP ruznych protistran: %d" % (udp_different))

    #print("INFO proverte rucne: IP %s - mozny UDP scan / attack - toku:%s   toku zpet:%s   ICMP unreach zpet:%s   ruzne cile:%s\n" % (i['val'], i['fl'], udp_back, udp_icmp_unreach, udp_different))
    print("INFO proverte rucne: IP %s - mozny UDP scan / attack - toku:%s   toku zpet:%s   ruzne cile:%s\n" % (i['val'], i['fl'], udp_back, udp_different))

  #kontrolne ICMP - vice nez 1/s
  nfStat=getStatNFData("(proto icmp or proto icmp6) and %s" % SRC_ISP, "srcip", minimum=60*TIME)
  print("\nDEBUG NetFlow data (ICMP): %s\n" % nfStat)

  #ICMP flooding - vice nez 100kbit/s
  nfStat=getStatNFData("(proto icmp or proto icmp6) and %s" % SRC_ISP, "srcip", poradi='bytes', minimum=100*1000/8*60*TIME)
  print("\nDEBUG NetFlow data (ICMP bytes): %s\n" % nfStat)
  for i in nfStat:
    print("INFO proverte rucne: IP %s odesila %.1f Mbit ICMP zprav - podezreni na flooding." % (i['val'], float(i['byt'])*8/60/TIME/1000/1000))

  #kontrolne dalsi protokoly nez TCP,UDP,ICMP - vize nez 1/10s
  nfStat=getStatNFData("not proto tcp and not proto udp and not proto icmp and not proto icmp6 and %s" % SRC_ISP, "srcip", minimum=60*TIME/10)
  print("\nDEBUG NetFlow data (protokoly mimo TCP,UDP,ICMP): %s\n" % nfStat)
