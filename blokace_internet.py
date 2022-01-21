#!/usr/bin/python3
#coding=utf8

"""
Popis: Viz. usage()
Autor: Jindrich Vrba
Dne: 19.1.2022
Posledni uprava: 21.1.2022
"""

import sys, signal, getpass, getopt, ipaddress
sys.path.append('/opt/lib')
import dtb
import newapi as api

#standardni chovani pri CTRL+C nebo ukonceni roury
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.SIG_DFL)


def usage(vystup):
  """ Použití programu
  @param vystup: Kam se bude vypisovat - nejběžněji sys.stderr nebo sys.stdout
  """
  vystup.write("""Blokace detekovaných útočníků.

  V části mojí diplomové práce se zabývám detekcí a blokací síťových útoků.
  Tento skript má za úkol na síťových zařízeních pravidelně aktualizovat seznam
  blokovaných adres pro přístup z internetu, ze kterých byly již dříve detekovány
  útoky.

Pouziti:
%s [-h|--help]
  \n""" % (sys.argv[0]))


def getFromDB(cursor):
  """ Z databáze získá aktuální seznam blokovaných IP adres nebo prefixů.
  @param cursor: Databázový kurzor.
  @return: Vrací sadu IP adres.
  """
  S=set()
  #vypsat aktualni stav z dtb
  cursor.execute("SELECT inet6_ntoa(IP),maska FROM net_blokace")
  rows = cursor.fetchall()
  for ip,maska in rows:
    print("DEBUG %20s/%d" % (ip, maska))
    #TODO maska 0 by se casem nemela vubec vyskytovat
    if (maska==0):
      S.add("%s" % (ip))
    else:
      S.add("%s/%d" % (ip, maska))
  return S


def getFromDevice(apiros):
  """ Získá aktuální seznam blokovaných IP adres nebo prefixů na zařízení s danou IP adresou.
  @param apiros: API spojení se zařízením, které nás zajímá.
  @return: Vrací sadu IP adres.
  """
  S=set()

  #postupne IPv4, IPv6
  for proto in ("ip","ipv6"):
    #print(proto)
    vysl=apiros.command(["/%s/firewall/address-list/print" % proto,"?list=blokace","?disabled=false"])
    for reply, attrs in vysl:
      if reply =="!re":
        #print("DEBUG: %s" % reply)
        #print("DEBUG: %s" % attrs["=address"])
        S.add(attrs["=address"])
      elif reply=="!done":
        None
      else:
        raise RuntimeError("ERROR %s: neocekavana odpoved \"%s\" s obsahem \"%s\"\n" % (apiros.ip,reply,str(attrs)))

  return S


def removeFromDevice(apiros, S):
  """ Na daném zařízení ddebere z blokovaných IP adres zadané IP adresy.
  @param apiros: API spojení se zařízením, které nás zajímá.
  @param S: Sada IP adres k odebrání.
  """
  for ip in S:
    print("DEBUG ip %s" % ip)
    #print("==IPv4? : %s" % isinstance(ipaddress.ip_network(ip), ipaddress.IPv4Network))

    #chovani pro IPv4/IPv6 je velmi podobne, jen je potreba provadet operace ve spravnem menu
    if isinstance(ipaddress.ip_network(ip), ipaddress.IPv4Network):
      proto="ip"
    else:
      proto="ipv6"

    #musime dohledat id
    zrus=apiros.command(["/%s/firewall/address-list/print" % proto,"?address=%s" % ip,"?list=blokace", "=.proplist=.id"])
    #print(zrus)

    #standardne vraci vysledek typu: [('!re', {'=.id': '*x'}), ('!done', {})]
    #pripadne pokud nebylo nalezeno: [('!done', {})]
    if (zrus[0][0]=='!re'):
      vysl=apiros.command(["/%s/firewall/address-list/remove" % proto,"=.id=%s" % zrus[0][1]["=.id"]])
      #print(vysl)
      if (vysl != [('!done', {})]):
        raise AssertionError("ERROR: Neocekavany vysledek mazani ip %s: %s" % (ip, str(vysl)))
    elif (zrus[0][0]=='!done'):
      print("INFO: ip %s nebyla v seznamu blokace nalezena" % ip)
    else:
      raise RuntimeError("ERROR: Neocekavany vysledek api dotazu: %s" % str(zrus))


def addToDevice(apiros, S):
  """ Na daném zařízení přidá k blokovaným IP adresám zadané IP adresy.
  @param apiros: API spojení se zařízením, které nás zajímá.
  @param S: Sada IP adres k přidání do seznamu.
  """
  for ip in S:
    print("DEBUG ip %s" % ip)

    #chovani pro IPv4/IPv6 je velmi podobne, jen je potreba provadet operace ve spravnem menu
    if isinstance(ipaddress.ip_network(ip), ipaddress.IPv4Network):
      proto="ip"
    else:
      proto="ipv6"

    vysl=apiros.command(["/%s/firewall/address-list/add" % proto, "=address=%s" % ip, "=list=blokace"])
    #print(vysl)
    if not (len(vysl[0])==2 and vysl[0][0] == '!done'):
      raise AssertionError("ERROR: Neocekavany vysledek vkladani na address list: %s" % str(vysl))


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

  conn=dtb.connect(charset="utf8", use_unicode=True)
  cursor = conn.cursor()

  #smazat jiz neaktualni blokace z dtb
  cursor.execute("delete FROM net_blokace where blokace_do<CURRENT_TIMESTAMP")

  S_dtb=getFromDB(cursor)
  print("DEBUG S_dtb: %s" % S_dtb)

  #TODO testovani na jednom zarizeni
  try:
    apiros = api.ApiRos("192.0.2.254")
    S_IP=getFromDevice(apiros)
  except RuntimeError as err:
    sys.stderr.write("%s" % err)
  else:
    print("DEBUG S_IP: %s" % S_IP)

  S_ubyly=S_IP-S_dtb
  print("DEBUG S_ubyly: %s" % S_ubyly)
  removeFromDevice(apiros, S_ubyly)

  S_pribyly=S_dtb-S_IP
  print("DEBUG S_pribyly: %s" % S_pribyly)
  addToDevice(apiros, S_pribyly)

  apiros.close()
