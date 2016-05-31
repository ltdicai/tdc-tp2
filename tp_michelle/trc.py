import time
from math import *
from scapy.all import *
from scipy.stats import t

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
for quantity_checked_routes in range(0,5):
	route = list()
	rtts_route = list()
	for i in range(1, 40):
		pkt = IP(dst=hostname, ttl=i) / ICMP()/"XXXXXXXdddfXXXX"
		start_time = time.time()
		# Send the packet and get a reply
		reply = sr1(pkt,verbose=0,timeout=4)
		sumatory_time_i_hopes = time.time() - start_time
		if reply is None:
			break
		elif reply.type == 0:
			route.append(reply.src)
			rtts_route.append(sumatory_time_i_hopes)
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
			print "%d hops away: " % i , reply.src
			route.append(reply.src)
			rtts_route.append(sumatory_time_i_hopes)
print "\n"

print "CALCULANDO RTTs PROMEDIO..."

print "\n"

routes_final_avgs_rtts = list()

for rttsOfRoute in listRttsNCountAppeared:
	avg_rtt_for_ips = list()
	count_appeared = rttsOfRoute[1]
	for ip_rtt in rttsOfRoute[0]:
		avg_rtt_for_ips.append(ip_rtt/count_appeared)
	routes_final_avgs_rtts.append(list((avg_rtt_for_ips,count_appeared)))

print routes
print routes_final_avgs_rtts
"""
#print "RUTAS Y PROMEDIOS DE RTTs POR HOP..."
#print "\n"
#i = 0
#for route in routes:
#	print "Ruta",i,": ", route
#	print "Muestras obtenidas para la ruta: ", routes_final_avgs_rtts[i][1]
#	print "RTT_i: ", routes_final_avgs_rtts[i][0]
#	listZRTTs = calcularZRTTS(routes_final_avgs_rtts[i][0])
#	print "ZRTT_i de la ruta:", listZRTTs
#	print "\n"
#	i = i+1
"""
