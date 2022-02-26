#!/usr/bin/python3
#coding=utf8

"""
Popis: Viz. usage()
Autor: Jindrich Vrba
Dne: 15.10.2021
Posledni uprava: 26.2.2022
"""

import sys, signal, getpass, getopt, subprocess, csv, os, ipaddress
from datetime import datetime, timedelta
sys.path.append('/opt/lib')
import dtb

#standardni chovani pri CTRL+C nebo ukonceni roury
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.SIG_DFL)

#jak casto jsou rotovany soubory s NetFlow daty
TIME=10 #[m]
#na jak dlouho blokovat detekované útočící IP
BLOCK_TIME="1 HOUR" #SQL formát
#maximální možný čas blokace
MAX_BLOCK_TIME="1 DAY" #SQL formát

#lokalni sit - zadat verejne rozsahy IPv4 i IPv6; neverejne rozsahy zde nema smysl zadavat
DST_LNET="(dst net 198.51.100.0/24 or dst net 2001:db8::/32)"


def usage(vystup):
  """ Použití programu
  @param vystup: Kam se bude vypisovat - nejběžněji sys.stderr nebo sys.stdout
  """
  vystup.write("""Detekce útoků z internetu do vnitřní sítě dle NetFlow dat.

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
  @param minimum: Získat jen záznamy s alespoň takovýmto počtem zadaného dle parametru poradi.
  @return: Seznam slovníků s daty. Klíčem slovníku je val a fl / ibyt, dle zadaneho poradi. Val je dle agregační funkce, fl je počet toků, ibyt je počet Bytů.
  """
  #dalsi poradi mozno pridat dle manualu nfdump parametr -s a klic dle parametru -o csv
  if (poradi=='flows'):
    klic='fl'
  elif (poradi=='bytes'):
    klic='ibyt'
  else:
    raise RuntimeError("ERROR Nezname poradi: '%s'!" % (poradi))

  #nacteni dat pomoci nfdump
  prikaz = ["nfdump","-M","/netflow-konektivity/%s" % netflow_adr_cist,"-r",SOUBOR,"-o","csv",filtr,"-s","%s/%s" % (agreg, poradi),"-n0"]
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


def setAttackers(L_blokovat):
  """ Aktualizuje informace o útočících IP adresách v databázi.
  Prvotní blokace je na 1 hodinu, pokud je IP adresa již blokována, blokace se o 1 hodinu prodlužuje.
  Přestože je IP adresa blokována, útoky z ní detekujeme.
  @param L_blokovat: Seznam s útočícími síťovými rozsahy (IP, maska).
  """
  print("DEBUG detekovano k blokaci %d adres: %s" % (len(L_blokovat), L_blokovat))

  conn=dtb.connect(charset="utf8", use_unicode=True)
  cursor = conn.cursor()

  for ip, maska in L_blokovat:
    #print("DEBUG %s/%d" % (ip, maska))
    cursor.execute("""
      INSERT INTO net_blokace (IP, maska, blokace_od, blokace_do)
      VALUES (inet6_aton('%s'), %d, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL %s)
      ON DUPLICATE KEY UPDATE blokace_do=blokace_do + INTERVAL %s
      """ % (ip, maska, BLOCK_TIME, BLOCK_TIME))

  #vypsat aktualni stav z dtb
  #cursor.execute("SELECT inet6_ntoa(IP), maska, blokace_od, blokace_do FROM net_blokace")
  #rows = cursor.fetchall()
  #for IP, maska, od, do in rows:
  #  print("DEBUG %20s/%d   %s   %s" % (IP, maska, od, do))
  cursor.close()
  conn.close()


def getBlockedForMaxTime():
  """ Získá seznam blokovaných na maximální možnou dobu.
  Takovým již nemá smysl dále prodlužovat čas blokace.
  @return: Seznam se síťovými rozsahy (IP, maska).
  """
  L=[]

  conn=dtb.connect(charset="utf8", use_unicode=True)
  cursor = conn.cursor()
  cursor.execute("""
    SELECT inet6_ntoa(IP), maska FROM net_blokace
    WHERE blokace_do > CURRENT_TIMESTAMP + INTERVAL %s
    """ % MAX_BLOCK_TIME)
  rows = cursor.fetchall()
  for IP, maska in rows:
    #print("DEBUG >max_doba: %20s/%d" % (IP, maska))
    L.append((IP, maska))

  cursor.close()
  conn.close()

  return L


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
  sys.stdout.write("DEBUG ctu z adresaru: %s\n\n" % netflow_adr_cist)
  if (netflow_adr_cist==""):
    sys.stderr.write("ERROR Nejsou dostupna zadna data, koncim!\n")
    sys.exit(1)

  #seznam k blokovani - detekovani utocnici
  L_blokovat=[]
  #seznam jiz blokovanych na maximalni dobu
  L_max_doba=getBlockedForMaxTime()
  print("DEBUG L_max_doba: %s" % L_max_doba)

  #TODO zkusebne neco vycist
  #nfData=getStatNFData("dst port 22 and %s" % DST_LNET, "srcip")
  #tmpPamet=sys.getsizeof(nfData)
  #for i in nfData:
  #  tmpPamet+=sys.getsizeof(i)
  #print('DEBUG NetFlow data maji velikost %d bytu' % tmpPamet)
  #print("DEBUG NetFlow data: %s" % nfData)


  #detekce ssh bruteforce z internetu - hledame neuspesna spojeni
  nfStat=getStatNFData("proto TCP and flags S and not flags UPF and dst port 22 and packets<2 and %s" % DST_LNET, "srcip", minimum=50)
  print("\nDEBUG NetFlow data (ssh): %s" % nfStat)
  for i in nfStat:
    #urcit masku dle protokolu
    if isinstance(ipaddress.ip_network(i['val']), ipaddress.IPv4Network):
      maska=32
    else:
      maska=128
    if ((i['val'],maska) in L_max_doba):
      print("DEBUG %s uz je blokovano na maximalni dobu, dale ji neproveruji\n" % i['val'])
      continue
    #print("DEBUG %s: %s" % (i['val'],i['fl']))
    ruznych=len(getStatNFData("proto TCP and flags S and not flags UPF and dst port 22 and packets<2 and src ip %s" % (i['val']), "dstip"))
    if (int(i['fl'])>200 or ruznych>10):
      print("DEBUG %s celkem %s neuspesnych spojeni na %d ruznych cilu" % (i['val'],i['fl'],ruznych))
      #kontrolne, provadi IP krome skenovani ssh i jina spojeni, ktera nejsou jen skenovani?
      debug=getStatNFData("src ip %s and not (proto TCP and dst port 22) and (not proto TCP or not (flags S and not flags UPF))" % (i['val']), "srcip")
      if (debug!=[]):
        tmp=int(debug[0]['fl'])
      else:
        tmp=0
      print("DEBUG spojeni %s mimo ssh: flows %d" % (i['val'], tmp))
      #dat na seznam, ty co chci blokovat - pokud provadi jen SYN scan, pripadne RST a nic jineho, tak blokovat
      if (tmp==0):
        L_blokovat.append((i['val'],maska))
        print("DEBUG pridavam k blokaci %s/%d\n" % (i['val'],maska))
      else:
        #TODO rucne proverit nepridane
        print("DEBUG NEpridavam k blokaci %s/%d\n" % (i['val'],maska))
        None


  #TODO Null scan - zatim jen kontrolne - sem tam se neco objevi, ale komunikuje se obema smery a oboje ma priznaky 'NULL'
  nfStat=getStatNFData("proto TCP and not flags ASRUPF and %s" % DST_LNET, "srcip", minimum=TIME*60)
  print("\nDEBUG NetFlow data (Null scan): %s\n" % nfStat)


  #SYN scan - vice nez 1/s nedokoncenych pozadavku na spojeni - zadna dokoncena spojeni
  nfStat=getStatNFData("proto TCP and flags S and not flags A and %s" % DST_LNET, "srcip", minimum=TIME*60)
  #print("\nDEBUG NetFlow data (SYN scan): %s\n" % nfStat)
  #projdeme vsechny takove IP z netu
  for i in nfStat:
    #print("DEBUG ip %s: flows %s" % (i['val'],i['fl']))
    #urcit masku dle protokolu
    if isinstance(ipaddress.ip_network(i['val']), ipaddress.IPv4Network):
      maska=32
    else:
      maska=128
    #zbytecne neproverovat jiz blokovane na max dobu
    if ((i['val'],maska) in L_max_doba):
      #print("DEBUG %s uz je blokovano na maximalni dobu, dale ji neproveruji\n" % i['val'])
      continue
    #vycist jen regulerni provoz, tedy ne SYN utok a ne jen RST a v teto situaci vynechat i toky o mene nez X paketech
    #TODO vytvorit funkci, ktera by jen zjistila pocet toku dle filtru?
    debug=getStatNFData("not ( (proto TCP and flags S and not flags A) or (proto TCP and flags R and not flags UAPSF) or packets<4 ) and %s and src ip %s" % (DST_LNET,i['val']), "srcip")
    if (debug!=[]):
      tmp_good=int(debug[0]['fl'])
    else:
      tmp_good=0
    #print("DEBUG good: flows %d" % (tmp_good))
    #dat na seznam, ty co chci blokovat - pokud nema zadne regulerni toky a zaroven skenuje alespon X cilu, tak blokovat
    if (tmp_good==0):
      L_blokovat.append((i['val'],maska))
      #print("DEBUG pridavam k blokaci %s/%d - %s toku\n" % (i['val'],maska,i['fl']))
    else:
      #TODO rucne proverit nepridane
      print("DEBUG NEpridavam k blokaci %s/%d - %s SYN toku, %d ok toku\n" % (i['val'],maska,i['fl'],tmp_good))
      None


  #TODO FIN scan - zatim jsem nic nenasel
  nfStat=getStatNFData("proto TCP and flags F and not flags ASRPU and packets<2 and %s" % DST_LNET, "srcip", minimum=0)
  print("\nDEBUG NetFlow data (FIN scan): %s\n" % nfStat)

  #TODO Xmas Tree scan - zatim jsem nic nenasel
  nfStat=getStatNFData("proto TCP and flags UPF and not flags ASR and packets < 2 and %s" % DST_LNET, "srcip", minimum=0)
  print("\nDEBUG NetFlow data (Xmas Tree scan): %s\n" % nfStat)


  #UDP skenovani / utok
  #S UDP je detekce problematicka, snazime se tedy odchytit pripady, ktere jsou ocividne a nenachazime zde regulerni komunikaci.
  #Detekujeme IP, ze kterych je mnoho toku s jen 1 paketem. Pokud obracenym smerem detekujeme minumum toku a zaroven se takto dana IP snazi
  #  komunikovat s mnoha nasimi IP adresami, je to adept na blokaci.
  nfStat=getStatNFData("proto UDP and packets<2 and %s" % DST_LNET, "srcip", minimum=TIME*60)
  #print("\nDEBUG NetFlow data (UDP scan / attack): %s\n" % nfStat)
  print("\nDEBUG NetFlow data (UDP scan / attack):\n")
  #Kvuli optimalizaci ziskame i UDP komunikaci obracenym smerem, jiz bez omezeni na 1 paket, optimalni je cca do 50% toku puvodniho dotazu. Kde hodnota nebude hodnota, vycte se zvlast.
  nfStat_pro_optimalizaci=getStatNFData("proto UDP", "dstip", minimum=TIME*60*0.5)
  #print("\nDEBUG optimalizace: %s\n" % nfStat_pro_optimalizaci)
  #projdeme vsechny podezrele IP z netu
  for i in nfStat:
    #print("DEBUG ip %s: flows %s" % (i['val'],i['fl']))
    #urcit masku dle protokolu
    if isinstance(ipaddress.ip_network(i['val']), ipaddress.IPv4Network):
      maska=32
    else:
      maska=128
    #zbytecne neproverovat jiz blokovane na max dobu
    if ((i['val'],maska) in L_max_doba):
      print("DEBUG %s uz je blokovano na maximalni dobu, dale ji neproveruji\n" % i['val'])
      continue

    #vycist UDP smerem od nasich zakazniku na tuto IP v internetu
    tmp_back=0
    #nejdriv se snazime najit v jiz vyctenych datech
    for j in nfStat_pro_optimalizaci:
      if (j['val']==i['val']):
        #print("DEBUG nalezeno")
        tmp_back=int(j['fl'])
        break
    #pokud hodnoty nemame, vycteme
    if (tmp_back==0):
      #print("DEBUG nutno vycist hodnotu obracenym smerem")
      debug=getStatNFData("proto udp and dst ip %s" % (i['val']), "dstip")
      if (debug!=[]):
        #print(debug)
        tmp_back=int(debug[0]['fl'])
      else:
        tmp_back=0
    #print("DEBUG UDP obracenym smerem: flows %d" % (tmp_back))
    #zajima nas jen kde je reakce max na 10% komunikace
    if (tmp_back >= int(0.1*int(i['fl']))):
      #print("DEBUG Mame alespon 10% UDP toku na tuto IP do internetu, jako smerem od ni s 1 paketem, to neni potreba dale resit.\n")
      continue

    #vycist pocet ruznych protistran
    debug=getStatNFData("proto udp and packets<2 and src ip %s" % (i['val']), "dstip")
    if (debug!=[]):
      #print(debug)
      tmp_different=len(debug)
    else:
      tmp_different=0
    #print("DEBUG UDP ruznych protistran: %d" % (tmp_different))
    #zajima nas jen kde se komunikuje minimalne s 20 ruznymi IP
    if (tmp_different <= 20):
      #print("Komunikuje jen s %d protistranami, u UDP nebudeme zasahovat, to je na ochranu u koncoveho uzivatele.\n" % (tmp_different))
      continue

    #TODO vycist regulerni toky, ktere nejsou UDP smerem z teto IP
    #u TCP ignorujeme viz SYN attack
    #ICMP typ zadavame zjednodusene - zajima nas unreachable, tedy ICMPv4 type 3 a ICMPv6 type 1 (odchyti to i ICMMPv6 type 3 Time Exceeded, ale to nevadi)
    debug=getStatNFData("src ip %s and not proto udp and (not proto tcp or (proto tcp and packets>1 and not (flags S and not flags A))) and not icmp-type 3 and not icmp-type 1" % (i['val']), "srcip")
    if (debug!=[]):
      #print(debug)
      tmp_notudp=int(debug[0]['fl'])
    else:
      tmp_notudp=0
    #print("DEBUG not UDP: %d" % (tmp_notudp))
    if (tmp_notudp>0):
      print("INFO Nemohu blokovat IP %s - nalezeno i %d toku, ktere nemusi byt utok - proverte rucne!.\n" % (i['val'], tmp_notudp))
      continue

    print("INFO blokace IP %s - UDP sken / utok - flows:%s   flows back:%s   different IP:%s   not UDP:%d\n" % (i['val'], i['fl'], tmp_back, tmp_different, tmp_notudp))
    L_blokovat.append((i['val'],maska))


  #kontrolne ICMP
  nfStat=getStatNFData("(proto icmp or proto icmp6) and %s" % DST_LNET, "srcip", minimum=TIME*60)
  print("\nDEBUG NetFlow data (ICMP): %s\n" % nfStat)


  #kontrolne dalsi protokoly nez TCP,UDP,ICMP
  nfStat=getStatNFData("not proto tcp and not proto udp and not proto icmp and not proto icmp6 and %s" % DST_LNET, "srcip", minimum=TIME*60)
  print("\nDEBUG NetFlow data (protokoly mimo TCP,UDP,ICMP): %s\n" % nfStat)


  #informacne datovy provoz nad X Mbit - dle zdrojove IP
  nfStat=getStatNFData("%s" % DST_LNET, "srcip", poradi='bytes', minimum=500*1000*1000/8*60*TIME)
  print("\nDEBUG NetFlow data (srcip/bytes): %s\n" % nfStat)
  if (nfStat!=[]):
    print('DEBUG rekord src bytes: %d Mbit (src IP %s)' % (int(nfStat[0]['ibyt'])*8/60/TIME/1000/1000, nfStat[0]['val']))


  #informacne datovy provoz nad X Mbit - dle cilove IP
  nfStat=getStatNFData("%s" % DST_LNET, "dstip", poradi='bytes', minimum=500*1000*1000/8*60*TIME)
  print("\nDEBUG NetFlow data (dstip/bytes): %s\n" % nfStat)
  if (nfStat!=[]):
    print('DEBUG rekord dst bytes: %d Mbit (dst IP %s)' % (int(nfStat[0]['ibyt'])*8/60/TIME/1000/1000, nfStat[0]['val']))


  #utocici IP adresy zaznamename do databaze
  setAttackers(L_blokovat)
