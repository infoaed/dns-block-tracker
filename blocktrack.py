#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import json, csv
import requests, dns.resolver

import random
from datetime import datetime

import pycountry
import pycountry_convert as pc

import os.path

TIMEOUT = 5 # sanity check timeout
LIFETIME = 0.5 # address poll lifetime

#REGION = [["NA", "SA", "AS", "OC", "AF", "EU"]
#REGION = [["EU"], ["EE", "LT", "LV", "PL", "FI", "SL", "HU", "RO", "MD", "RU"]]
#REGION = [["EU"], ["EE", "LT", "LV", "PL", "FI"]]
#REGION = [["EU"]]

REGION = [["EU"], ["EE", "LT", "LV"]]
STRICT = False

SANITY_TEST_DOMAIN = {'name': 'w3.org', 'ip': '128.30.52.100'}

# calculate percentage of blocked addresses, set pass flag

def coef_calc(check_list, resolved):
  count = resolved['ok'] + resolved['fail']
  
  if count == 0:
    percent = 0
  else:
    percent = round(resolved['fail'] / count, 2)
  coef = count > len(check_list)/3 and percent > 0.50
  
  return coef, percent

time_str = datetime.now().strftime("%Y-%m-%d")
region_str = "".join(REGION[0])
if len(REGION)>1:
  region_str += "_" + "".join(REGION[1])

created = False

# public dns list from: https://public-dns.info/
dns_list_url = 'https://public-dns.info/nameservers.json'
dns_list_file = dns_list_url.rsplit('/',1)[1]

if not os.path.isfile(dns_list_file):
  r = requests.get(dns_list_url, allow_redirects=True)
  with open(dns_list_file, 'wt') as data_file:
    data_file.write(r.text)
with open(dns_list_file) as data_file:
  dns_list = json.load(data_file)
  
# custom list: ~ https://www.lifewire.com/free-and-public-dns-servers-2626062
with open("popular-dns.json") as data_file:
  dns_pop = json.load(data_file)
  dns_list.extend(dns_pop)
  
random.shuffle(dns_list)

# https://www.facebook.com/boamaod/posts/10209271344776893?comment_id=10209281381987817

euro_list = ["www.rt.com", "de.rt.com", "francais.rt.com", "actualidad.rt.com", "arabic.rt.com", "doc.rt.com", "lv.sputniknews.com", "sputniknews.com", "sputniknews.ru", "sputniknews.lt", "sputniknews.ee", "sputniknews.gr", "sputniknews.kz", "sputniknews.cn", "sputniknews.lv.com", "sputniknewslv.com", "sputnik.by", "sputnik.kz", "sputnik.az", "sputnik.az", "sputnik-news.ee", "sputnik-meedia.ee", "armeniasputnik.am", "sputnik-abhazia.info", "sputnik-ossetia.com", "sputnik-georgia.com", "sputniknews-uz.com", "sputnik-tj.com", "rbth.com", "rtd.rt.com", "russian.rt.com", "rt.com"]

# https://www.ttja.ee/uudised/ttja-piirab-ligipaasu-seitsmele-vaenu-ohutavale-veebilehele
# https://p6drad-teel.net/~p6der/ettekirjutus-internetiuhenduse-teenuse-pakkujatele.pdf

ttja_list = ["ntv.ru", "ren.tv", "5-tv.ru", "78.ru", "1tv.com", "lenta.ru", "tass.ru"]

# https://www.neplpadome.lv/lv/sakums/padome/padomes-sedes/sedes-sadalas/neplp-saistiba-ar-apdraudejumu-valsts-drosibai-ierobezo-71-timeklvietni-latvija.html

neplp_list = ["rueconomics.ru", "rusvesna.su", "slovodel.com", "ura.news", "octagon.media", "sputnik.by", "www.ntv.ru", "kremlin.ru", "www.m24.ru", "ura.news", "mainampasauli.news", "riafan.ru", "tass.ru", "ng.ru", "vz.ru", "argumenti.ru", "kp.ru", "lenta.ru", "rubaltic.ru", "vesti.ru", "aif.ru", "gazeta.ru", "iz.ru", "interfax.ru", "balticword.com", "news-front.info", "topwar.ru", "nation-news.ru", "politros.com", "www.ridus.ru", "ivbg.ru", "neva.today", "zelv.ru", "news.ru", "360tv.ru", "russian7.ru", "tvzvezda.ru", "radiokp.ru", "www.sputnikfm.ru", "moskva.fm", "www.radiorus.ru", "radiovesti.ru", "www.bfm.ru", "govoritmoskva.ru", "radiopotok.ru", "kprf.vrn.ru", "radio1.news", "www.souzveche.ru", "gtrklnr.com", "utro.ru", "imhoclub.lv", "lv.imhoclub.com", "imhoclub.by", "sputnik-meedia.ee", "russian.rt.com", "eadaily.com", "rg.ru", "rcb.ru", "pravda.ru", "theduran.com", "belta.by", "rentv.ru", "exclav.ruplayyerplayer.php", "inosmi.ru", "newsinform.com", "www.opednews.com", "usrussiaaccord.org", "vestikavkaza.ru", "rus-news.net", "radiozvezda.ru", "top-radio.ru"]

check_list = []

check_list.extend(euro_list)
check_list.extend(ttja_list)
check_list.extend(neplp_list)

spread = {}

dns_fail = {'timeout': 0, 'badresponse': 0, 'refused': 0, 'nohost': 0, 'noresponse': 0, 'sanity': 0}
dns_fail_poll = {'timeout': 0, 'badresponse': 0, 'refused': 0, 'nohost': 0, 'noresponse': 0, 'sanity': 0}

for d in dns_list:
  
  ip = d['ip']

  if len(d['as_org']) > 0:
    org = d['as_org']
  elif len(d['name'].strip()) > 0:
      org = d['name']
  else:
      org = ip
      
  code = None
  cont = None
  resolved = {'fail': 0, 'ok': 0}
  
  # find location
  
  if 'country_id' in d and len(d['country_id'].strip()) > 0:
    code = d['country_id'].strip()
    try:
      cont = pc.country_alpha2_to_continent_code(code)
    except KeyError:
      
      if STRICT:
        continue
    
    # check continent
    
    if len(REGION) > 0:
      if cont is None:
        if STRICT:
          continue
      elif cont not in REGION[0]:
        continue
    
    # check country
        
    if len(REGION) > 1:
      if code not in REGION[1]:
        if cont is None and not STRICT:
          pass
        else:
          continue
          
  elif STRICT:
    continue

  if code is None:
    code = "--"
    cont = "~~"
  elif cont is None:
    cont = "~~"

  # is dns server giving meaningful answers?
  # if not, jump to next
  
  #print("###", code, cont, ip, org)
    
  n = dns.name.from_text(SANITY_TEST_DOMAIN['name'])
  q = dns.message.make_query(n, dns.rdatatype.A)
  try:
    r = dns.query.udp(q, ip, timeout = TIMEOUT)
  except dns.exception.Timeout:
    m = 'timeout'
    dns_fail[m] += 1
    continue
  except dns.query.BadResponse:
    m = 'badresponse'
    dns_fail[m] += 1
    continue
  except ConnectionRefusedError:
    m = 'refused'
    dns_fail[m] += 1
    continue
  except OSError:
    m = 'nohost'
    dns_fail[m] += 1
    continue

  try:
    #print(r)
    ns_rrset = r.find_rrset(r.answer, n, dns.rdataclass.IN, dns.rdatatype.A)
    if len(ns_rrset) > 0:
      x = ns_rrset[0]
  except KeyError:
    m = 'noresponse'
    dns_fail[m] += 1
    continue
    
  if str(x) != SANITY_TEST_DOMAIN['ip']:
    m = 'sanity'
    dns_fail[m] += 1
    continue

  # yes, it does => init
  
  spt = False
  rt = False
  euro = {'fail': 0, 'ok': 0}
  ttja = {'fail': 0, 'ok': 0}
  neplp = {'fail': 0, 'ok': 0}
  
  row = [code, cont, org]
  print(f"{code}, {cont}, {org}, ", end='', flush=True)
  
  # try resolving dns record for each blocklist address
  
  m = False
  
  for c in check_list:
        
    x = None
    
    n = dns.name.from_text(c)
    q = dns.message.make_query(n, dns.rdatatype.A)
    try:
      r = dns.query.udp(q, ip, timeout = LIFETIME)
    except dns.exception.Timeout:
      dns_fail_poll['timeout'] += 1
    except dns.query.BadResponse:
      m = 'badresponse'
      dns_fail_poll[m] += 1
      break
    except ConnectionRefusedError:
      m = 'refused'
      dns_fail_poll[m] += 1
      break
    except OSError:
      m = 'nohost'
      dns_fail_poll[m] += 1
      break

    try:
      ns_rrset = r.find_rrset(r.answer, n, dns.rdataclass.IN, dns.rdatatype.A)
      if len(ns_rrset) > 0:
        if str(ns_rrset[0]) not in ("127.0.0.1", '0.0.0.0', ip) and len(str(ns_rrset[0])) >= 7:
        
          # resolved
          x = ns_rrset[0]
        
    except KeyError:
      pass    
    
    if x is None:
      
      if c == "rt.com":
        rt = True
      elif c == "sputniknews.ru":
        spt = True
        
      status = 'fail'

    else:

      status = 'ok'

    resolved[status] += 1
    if c in euro_list:
      euro[status] += 1
    if c in ttja_list:
      ttja[status] += 1
    if c in neplp_list:
      neplp[status] += 1
  
  # poll time error, exclude from stats
  
  if m:
    print(r)
    print(m.upper())
    continue
      
  # print stats

  all_flag, all_perc = coef_calc(check_list, resolved)
  euro_flag, euro_perc = coef_calc(euro_list, euro)
  ee_flag, ee_perc = coef_calc(ttja_list, ttja)
  lv_flag, lv_perc = coef_calc(neplp_list, neplp)
  
  cat_three = (euro_flag + ee_flag + lv_flag) / 3
  cat_five = (rt + spt + euro_flag + ee_flag + lv_flag) / 5
  
  data = [int(rt), int(spt), all_perc, resolved['ok'], resolved['fail'], int(all_flag), euro_perc, euro['ok'], euro['fail'], int(euro_flag), ee_perc, ttja['ok'], ttja['fail'], int(ee_flag), lv_perc, neplp['ok'], neplp['fail'], int(lv_flag), round(cat_three,2), round(cat_five,2)]
  
  row.extend(data)

  print(str(data)[1:-1])

  if cont not in spread:
    spread[cont] = [cont, 0, 0]
  if code not in spread:
    spread[code] = [code, 0, 0]

  spread[code][1] += 1-cat_five
  spread[code][2] += cat_five

  spread[cont][1] += 1-cat_five
  spread[cont][2] += cat_five

  if not created:
    with open(f"{time_str}_{region_str}_stats.csv", "w") as csv_file:
      head = ["State", "Continent", "Owner", "RT.com", "Spt.ru", "All %", "OK", "Fail", "Flag", "Euro %", "OK", "Fail", "Flag", "TTJA %", "OK", "Fail", "Flag", "NEPLP %", "OK", "Fail", "Flag", "Cat3 %", "Cat5 %"]
      csv.writer(csv_file, delimiter=";").writerow(head)
      created = True

  with open(f"{time_str}_{region_str}_stats.csv", "a") as csv_file:
    csv.writer(csv_file, delimiter=";").writerow(row)
    
  with open(f"{time_str}_{region_str}_stats-summary.csv", "w") as csv_file:
      writer = csv.writer(csv_file, delimiter=";")
      for row in spread:
          writer.writerow(spread[row])
  
  with open(f"{time_str}_{region_str}_stats-error.json", "w") as json_file:
    error_dict = {'init': dns_fail, 'poll_time': dns_fail_poll }
    json_file.write(json.dumps(error_dict, indent=2))

print(spread)
print(dns_fail)
print(dns_fail_poll)