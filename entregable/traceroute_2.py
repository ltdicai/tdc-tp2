# -*- coding: utf-8 -*-
import time
from math import *
from scapy.all import *
from modified_thompson import thompson_tau_test
from urllib2 import urlopen
from collections import defaultdict
import json
import csv

######## Para correr Script: sudo python traceroute_estimatedRtt_n_zrtt.py 'ip' ########
######## Ejemplo:  sudo python traceroute_estimatedRtt_n_zrtt.py 23.12.153.99   ########

url = "http://freegeoip.net/json/"
CACHE_PAISES = dict()

try:
	with open("archivo.csv", "r") as csvfile:
		for linea in csvfile:
			(ip, pais) = linea.split(",")
			CACHE_PAISES[ip] = pais.strip()
except IOError:
	pass

print CACHE_PAISES

def obtener_pais(ip):
	if str(ip) in CACHE_PAISES:
		return CACHE_PAISES[str(ip)]
	else:
		for intento in xrange(3):
			try:
				response = urlopen(url + str(ip))
				print ip
				res_json = json.load(response)
				print res_json
				country_name = str(res_json["country_name"])
				if not country_name:
					continue
				with open("archivo.csv", "a") as csvfile:
					csvfile.write("{0},{1}\n".format(ip, country_name))
				CACHE_PAISES[str(ip)] = country_name
				return country_name
			except Exception, exc:
				print exc
				continue
		print "No obtuve respuesta"
		return "Unknown"



def rtt_a_str(rtt):
	return str(round(rtt*1000, 3)) + " ms"

def mostrar_RTTs(rtts):
	res = list()
	for elem in rtts:
		if type(elem) is str:
			item = elem
		else:
			item = "{ip} {rtt}".format(ip=elem['ip'], rtt=rtt_a_str(elem['rtt']))
		res.append(item)
	return "\t".join(res)

CANT_RUTAS = 1
MAX_TTL = 30
TAM_RAFAGA = 3
TIMEOUT = 5

hostname = str(sys.argv[1])

RTT_por_hop = defaultdict(list)
muestras = dict()

rutas = list()
for corrida in range(CANT_RUTAS):
	ruta_actual = list()
	rtts_ruta_actual = list()
	for ttl in xrange(1, MAX_TTL):
		muestras[ttl] = defaultdict(list)
		pkt = IP(dst=hostname, ttl=ttl) / ICMP()/"XXXXXXXdddfXXXX"
		for i in xrange(TAM_RAFAGA):
			t_inicio = time.time()
			reply = sr1(pkt, verbose=0, timeout=TIMEOUT)
			t_final = time.time() - t_inicio
			if reply:
				muestras[ttl][str(reply.src)].append(t_final)
			else:
				continue

	camino = list()
	for ttl, d in muestras.items():
		if muestras[ttl]:
			max_ip = None
			max_length = 0
			for ip, lista_rtt in d.items():
				if len(lista_rtt) > max_length:
					max_ip = ip
					max_length = len(lista_rtt)
			rtt = sum(d[ip])/max_length
			camino.append({'ip': ip, 'rtt': rtt})
		else:
			camino.append({'ip': "unknown", 'rtt': 'unknown' })
"""
		print "{ttl} {rtts}\t(avg={rtt_prom})".format(
				ttl=ttl,
				rtts=mostrar_RTTs(RTT_por_hop[ttl]),
				rtt_prom=(reply and rtt_a_str(acum/respuestas_recibidas)) or "*"
		)
		if reply is None:
			continue
		rtt_promedio = acum/respuestas_recibidas
		if reply.type == 0:
			# Echo reply
			ruta_actual.append(reply.src)
			rtts_ruta_actual.append(rtt_promedio)
			print "Llegue a:", hostname, reply.src
			break
		else:
			# Time exceed
			ruta_actual.append(reply.src)
			rtts_ruta_actual.append(rtt_promedio)
print "\n"

print "RTTs:", rtts_ruta_actual

print "Geolocalizando:"

countries_por_hop = dict()
for ttl, elems in RTT_por_hop.items():
	countries_por_hop[ttl] = list()
	for elem in elems:
		if type(elem) is str:
			continue
		ip = elem['ip']
		print "Obteniendo pais para", str(ip)
		countries_por_hop[ttl].append({'ip': ip, 'country': obtener_pais(ip)})

print "Paises por hop:"
for ttl, elems in countries_por_hop.items():
	print "TTL={0}".format(ttl)
	for elem in elems:
		if type(elem) is str:
			continue
		print "{ip} -> {country}".format(**elem)

print "Buscando outliers"
res2 = []
res2.append(round(rtts_ruta_actual[0], 4))
for i in xrange(1, len(rtts_ruta_actual)):
    res2.append(abs(round(rtts_ruta_actual[i] - rtts_ruta_actual[i-1], 4)))

print "RTT relativos:", res2
outliers = thompson_tau_test(res2)
print "Outliers:"
print outliers
for elem in outliers:
	if elem > 0:
		print "De {0}({1}) a {2}({3})".format(
			ruta_actual[elem-1],
			CACHE_PAISES.get(ruta_actual[elem - 1], "Unknown"),
			ruta_actual[elem],
			CACHE_PAISES.get(ruta_actual[elem], "Unknown")
		)
"""
