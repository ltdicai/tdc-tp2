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

def obtener_pais(ip):
	if str(ip) in CACHE_PAISES:
		return CACHE_PAISES[str(ip)]
	else:
		for intento in xrange(3):
			try:
				response = urlopen(url + str(ip))
				res_json = json.load(response)
				print res_json
				with open(archivo, "w") as csvfile:
					csvfile.write("{0},{1}".format(ip, str(res_json['country_name'])))
				CACHE_PAISES[str(ip)] = str(res_json["country_name"])
				return res_json["country_name"]
			except:
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

def estaLaRuta(routes,route):
	for i in range(len(routes)):
		if(routes[i] == route):
			return True
	return False

def dameIndiceRoute(routes, route):
	indice_res = 0
	while(routes[indice_res] != route):
		indice_res = indice_res+1
	return indice_res

def calcularVarianza(list_muestras, hastai, media):
	sumatoria = 0
	hastai = hastai + 1
	for i in range(0, hastai):
		sumatoria += math.pow((list_muestras[i]-media),2)
	return sumatoria/(hastai)

def calcularRttBarra(list_muestras,  hastai):
	sumatoria = 0
	hastai = hastai + 1
	for i in range(0, hastai):
		sumatoria += list_muestras[i]
	return sumatoria/(hastai)

def calcularZRTTS(avgs_rtts_of_route):
	listRes = list()
	listRes.append(0) #el primer zrtt siempre es 0, esta indefinido, el segundo zrtt tambien es 0, da 0 el desvio
	listRes.append(0)
	for i in range(2, len(avgs_rtts_of_route)):
		rtt_barra = calcularRttBarra(avgs_rtts_of_route,i-1)
		srtt = 	math.sqrt(calcularVarianza(avgs_rtts_of_route, i-1,rtt_barra))
		listRes.append((avgs_rtts_of_route[i]-rtt_barra)/srtt)
	return listRes

CANT_RUTAS = 1
MAX_TTL = 30
TAM_RAFAGA = 3
TIMEOUT = 5

hostname = str(sys.argv[1])
listRttsNCountAppeared = list()

RTT_por_hop = defaultdict(list)


#termine = 0
rutas = list()
rtts_of_routes = list()
indice_de_ruta = 0
for corrida in range(CANT_RUTAS):
	ruta_actual = list()
	rtts_ruta_actual = list()
	for ttl in xrange(1, MAX_TTL):
		pkt = IP(dst=hostname, ttl=ttl) / ICMP()/"XXXXXXXdddfXXXX"
		acum = 0
		respuestas_recibidas = 0
		alguna_respuesta = None
		rtts = ["*" for i in xrange(TAM_RAFAGA)]
		for i in xrange(TAM_RAFAGA):
			t_inicio = time.time()
			reply = sr1(pkt, verbose=0, timeout=TIMEOUT)
			t_final = time.time() - t_inicio
			if reply:
				RTT_por_hop[ttl].append({'ip': reply.src, 'rtt': t_final})
				alguna_respuesta = reply
				respuestas_recibidas += 1
				acum += t_final
				rtts[i] = t_final
			else:
				RTT_por_hop[ttl].append("*")
		reply = alguna_respuesta
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
			print "Llegue a:", hostname, reply.src,  reply.type
			if not estaLaRuta(rutas, ruta_actual):
				num_de_proxima_ruta = len(rutas)
				rutas.append(ruta_actual)
				print "Ruta nueva: ", ruta_actual
				#listRttsNCountAppeared.append(list((rtts_route,1)))
			else:
				print "Ruta existente, nueva muestra de rtts para la misma, acumulo..."
				index = dameIndiceRoute(routes, route)
				valueOfRouteDicc = listRttsNCountAppeared[index]
				rttListOfRoute = valueOfRouteDicc[0]
				cantAppeared = valueOfRouteDicc[1]

				for i in range(len(rttListOfRoute)):
					rttListOfRoute[i] = rttListOfRoute[i] + rtts_route[i]
				listRttsNCountAppeared[index] = list((rttListOfRoute, cantAppeared+1))
			break
		else:
			#print "Recibimos un time exceeded"
			#print "%d hops away: " % ttl , reply.src
			ruta_actual.append(reply.src)
			rtts_ruta_actual.append(rtt_promedio)
print "\n"

print "RTTs:", rtts_ruta_actual

print "Geolocalizando:"
"""
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
		print "{ip} -> {country}"(**elem)
"""
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
		print "De {0}({1}) a {2}({3})".format(ruta_actual[elem-1], ruta_actual[elem])
		#print "De {0}({1}) a {2}({3})".format(route[elem-1], countries[route[elem-1]] ,route[elem], countries[route[elem]])
