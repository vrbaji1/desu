# Detekce a eliminace síťových útoků (DESU)

Detekce a eliminace síťových útoků prostřednictvím NetFlow sleduje kompletní síťové toky v síti pokytovatele internetu a snaží se odhalit útoky.

## detekce.py

Detekce útoků z vnitřní sítě se provádí z NetFlow dat posbíraných na hlavních bodech na rozhraních směrem k zákazníkům.
Cílem detekce je detekovat různé síťové útoky a upozornit na ně obsluhu.

```
Použití:
detekce.py [soubor]
detekce.py [-h|--help]

soubor ... číst data z konkrétního souboru, zadává se ve formátu 2022-02-24/nfcapd.202202240400
pokud není soubor zadán, čtou se aktuální data
```

## detekce_internet.py

Detekce útoků z internetu do vnitřní sítě se provádí z NetFlow dat posbíraných na páteřních rozhraních s konektivitami. 
Při jednotlivých detekcích se hledají IP adresy v internetu, které provádí daný útok.
Než se přistoupí k blokaci takto nalezených IP adres, je nutné provézt kontrolu, jestli s nimi neprobíhá legitimní komunikace.

```
Použití:
detekce_internet.py [soubor]
detekce_internet.py [-h|--help]

soubor ... číst data z konkrétního souboru, zadává se ve formátu 2022-02-24/nfcapd.202202240400
pokud není soubor zadán, čtou se data z aktuálního souboru
```

## blokace_internet.py

Blokace má za úkol na síťových zařízeních pravidelně aktualizovat seznam blokovaných adres pro přístup z internetu.

```
Použití:
blokace_internet.py [-h|--help]
```

## kontrola_spam.py

Detekce rozesílání nevyžádané pošty se provádí přímo na hlavních routerech v jednotlivých oblastech.
Tento skript má za úkol kontrolovat stav blokace na těchto routerech, o vzniklé nebo ukončené blokaci informovat zákazníky, a evidovat informace v databázi.

```
Použití:
kontrola_spam.py [-h|--help]
```

## Spouštění plánovačem

Detekce, blokace i kontrola se běžně spouští pravidelně plánovačem Cron. Detekce z vnitřní sítě jednou za deset minut, detekce z internetu následovaná blokací pak každou minutu. Kontrola blokace rozesílání nevyžádané pošty stačí jednou za půl hodiny:

```
*/10 *  * * *   non-root-user /opt/detekce_utoky/detekce.py
*    *  * * *   non-root-user /opt/detekce_utoky/detekce_internet.py && /opt/detekce_utoky/blokace_internet.py
*/30 *  * * *   non-root-user /opt/detekce_utoky/kontrola_spam.py
```
