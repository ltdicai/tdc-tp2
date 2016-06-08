# -*- coding: utf-8 -*-
import time
from math import *
from scapy.all import *
from modified_thompson import thompson_tau_test
from urllib2 import urlopen
import json

######## Para correr Script: sudo python traceroute_estimatedRtt_n_zrtt.py 'ip' ########
######## Ejemplo:  sudo python traceroute_estimatedRtt_n_zrtt.py 23.12.153.99   ########


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


hostname = str(sys.argv[1])
listRttsNCountAppeared = list()

termine = 0
routes = list()
rtts_of_routes = list()
indice_de_ruta = 0
for quantity_checked_routes in range(0,1):
	route = list()
	rtts_route = list()
	for i in range(1, 30):
		pkt = IP(dst=hostname, ttl=i) / ICMP()/"XXXXXXXdddfXXXX"
		print "Mandando un paquete con ttl", i
		acum = 0
		respuestas = 0
		alguna_respuesta = None
		rtts = ["*" for i in xrange(11)]
		for j in xrange(11):
			start_time = time.time()
			reply = sr1(pkt, verbose=0, timeout=2)
			if reply:
				alguna_respuesta = reply
				respuestas += 1
				rtt = time.time() - start_time
				acum += rtt
				rtts[j] = rtt
		reply = alguna_respuesta
		if reply is None:
			print "No recibí respuesta, seguimos"
			continue
		rtt_promedio = acum/respuestas
		print "Tardé en PROMEDIO", rtt_promedio
		print rtts
		if reply.type == 0:
			route.append(reply.src)
			rtts_route.append(rtt_promedio)
			print "Llegue a:", hostname, reply.src,  reply.type
			if not estaLaRuta(routes, route):
				num_de_proxima_ruta = len(routes)
				routes.append(list((route)))
				print "Ruta nueva: ", route

				listRttsNCountAppeared.append(list((rtts_route,1)))
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
			print reply.type
			print "Respondieron y no es el nodo que buscamos"
			print "%d hops away: " % i , reply.src
			route.append(reply.src)
			rtts_route.append(rtt_promedio)
print "\n"

print rtts_route

print "Buscando outliers"
res2 = []
res2.append(round(rtts_route[0], 4))
for i in xrange(1, len(rtts_route)):
    res2.append(abs(round(rtts_route[i] - rtts_route[i-1], 4)))

url = "http://freegeoip.net/json/"

countries = {}
for ip in route:
	for pe in xrange(3):
		try:
			response = urlopen("http://freegeoip.net/json/" + str(ip))
			countries[str(ip)] = json.load(response)["country_name"]
			print countries[str(ip)]
		except:
			if pe == 2:
				break


print "Muestra", res2
outliers = thompson_tau_test(res2)
print "Outliers:"
for elem in outliers:
	if elem > 0:
		print "De {0}({1}) a {2}({3})".format(route[elem-1], countries[route[elem-1]] ,route[elem], countries[route[elem]])
	#print route[elem], "({0})".format(res2[elem])

print "\n"

# routes_final_avgs_rtts = list()
#
# for rttsOfRoute in listRttsNCountAppeared:
# 	avg_rtt_for_ips = list()
# 	count_appeared = rttsOfRoute[1]
# 	for ip_rtt in rttsOfRoute[0]:
# 		avg_rtt_for_ips.append(ip_rtt/count_appeared)
# 	routes_final_avgs_rtts.append(list((avg_rtt_for_ips,count_appeared)))
#
# print "RUTAS Y PROMEDIOS DE RTTs POR HOP..."
# print "\n"
# i = 0
# for route in routes:
# 	print "Ruta",i,": ", route
# 	print "Muestras obtenidas para la ruta: ", routes_final_avgs_rtts[i][1]
# 	print "RTT_i: ", routes_final_avgs_rtts[i][0]
# 	listZRTTs = calcularZRTTS(routes_final_avgs_rtts[i][0])
# 	print "ZRTT_i de la ruta:", listZRTTs
# 	print "\n"
# 	i = i+1
