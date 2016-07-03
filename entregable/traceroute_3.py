# -*- coding: utf-8 -*-
import time
from math import *
from scapy.all import *
from scapy.config import conf
from modified_thompson import thompson_tau_test
from urllib2 import urlopen
from collections import defaultdict
import json
import csv

######## Para correr Script: sudo python traceroute_estimatedRtt_n_zrtt.py 'ip' ########
######## Ejemplo:  sudo python traceroute_estimatedRtt_n_zrtt.py 23.12.153.99   ########
hostname = str(sys.argv[1])

#Constantes
URL = "http://freegeoip.net/json/"
CANT_RUTAS = 1
MAX_TTL = 30
TAM_RAFAGA = 100
TIMEOUT = 3
ECHO_REPLY = 0


rtt_por_hop = defaultdict(list)
cache_paises = dict()
muestras = dict()

def obtener_pais(ip):
    if ip is None:
        return None

    ip = str(ip).strip()
    if not cache_paises:
        try:
            with open("archivo.csv", "r") as csvfile:
                for linea in csvfile:
                    (ip, pais) = linea.split(",")
                    cache_paises[ip] = pais.strip()
        except IOError:
            pass
    if ip in cache_paises:
        return cache_paises[ip]
    else:
        for intento in xrange(3):
            try:
                response = urlopen(URL + str(ip), None, 3)
                res_json = json.load(response)
                country_name = str(res_json["country_name"])
                if not country_name:
                    continue
                with open("archivo.csv", "a") as csvfile:
                    csvfile.write("{0},{1}\n".format(ip, country_name))
                cache_paises[ip] = country_name
                return country_name
            except Exception, exc:
                continue
        return None



def pasar_a_ms(num):
    return "{0:>7} ms".format(str(round(num*1000, 3)))

def mostrar_RTTs(rtts):
    res = list()
    for elem in rtts:
        if type(elem) is str:
            item = elem
        else:
            item = "{ip} {rtt}".format(ip=elem['ip'], rtt=pasar_a_ms(elem['rtt']))
        res.append(item)
    return "\t".join(res)


t_t_inicio = time.time()
destino_alcanzado = False
for ttl in xrange(1, MAX_TTL):
    if destino_alcanzado:
        break
    muestras[ttl] = defaultdict(list)
    pkt = IP(dst=hostname, ttl=ttl) / ICMP()/"XXXXXXXdddfXXXX"
    reply = None
    for i in xrange(TAM_RAFAGA):
        print "TTL: {0:>3d} | #PKT: {1:>3d}".format(ttl, i)
        t_inicio = time.time()
        reply = sr1(pkt, verbose=0, timeout=TIMEOUT)
        t_final = time.time() - t_inicio
        if reply:
            muestras[ttl][str(reply.src)].append(t_final)
            if reply.type == ECHO_REPLY:
                destino_alcanzado = True
        else:
            muestras[ttl][None].append(t_final)
t_t_final = time.time() - t_t_inicio

print "Se completó el rastreo en {0} segundos".format(t_t_final)

muestreo = dict()
for ttl, respuestas in muestras.items():
    muestreo[ttl] = list()
    for ip, rtts in respuestas.items():
        rtt_promedio = sum(rtts)/len(rtts)
        muestreo[ttl].append({'ip': ip, 'cant_respuestas': len(rtts), 'rtts':rtts, 'rtt_promedio': rtt_promedio})

#Generamos el camino estimado, usando para cada TTL el nodo
#que devolvio mas respuestas
camino = list()
for ttl, respuestas in muestreo.items():
    maximo = 0
    pais = None
    ip = None
    if len(respuestas) == 1:
        respuesta = respuestas[0]
        ip = respuesta['ip']
        maximo = respuesta['cant_respuestas']
        rtt_promedio = respuesta['rtt_promedio']
    else:
        for respuesta in respuestas:
            if respuesta["ip"] is not None and respuesta['cant_respuestas'] > maximo:
                ip = respuesta['ip']
                maximo = respuesta['cant_respuestas']
                rtt_promedio = respuesta['rtt_promedio']
    pais = obtener_pais(ip)
    camino.append({'ttl': ttl, 'ip': ip, 'rtt': rtt_promedio, 'pais': pais})

rtt_relativos = list()
camino_aux = [(item["ip"], item["rtt"], item["ttl"]) for item in camino if item["ip"] is not None]
ip_relativos = list()
saltos = list()
for i in xrange(1, len(camino_aux)):
    origen = camino_aux[i-1]
    destino = camino_aux[i]
    rtt_relativos.append(abs(destino[1]- origen[1]))
    #ip_relativos.append(('({0}) {1}'.format(origen[2], origen[0]), '({0}) {1}'.format(destino[2], destino[0])))
    ip_relativos.append((origen[0], destino[0]))
    saltos.append((origen[2], destino[2]))

#Obtenemos los outliers
outliers = thompson_tau_test(rtt_relativos)


#Outputs
print muestreo
print '\n'
with open(hostname + "_muestreo.csv", "w+") as muestreofile:
    muestreofile.write("Muestreo\n")
    for ttl, respuestas in muestreo.items():
        temp = { ttl: [{'ip': respuesta['ip'], 'cant_respuestas': respuesta['cant_respuestas'], 'rtt_promedio': respuesta['rtt_promedio']} for respuesta in respuestas]}
        print temp
        muestreofile.write(str(temp)+"\n")

with open(hostname + "_camino.csv", "w+") as caminofile:
    titulo = "Camino:\n---------------"
    header = "{3}\t{0:^20s}\t{1:^20s}\t{2}".format('Pais', 'IP', 'RTT', 'TTL')
    caminofile.write(titulo)
    caminofile.write(header)
    print "\n" + titulo
    print header
    for hop in camino:
        temp = "{3:>2}\t{0:>20s}\t{1:<20s}\t{2}".format(hop["ip"], hop["pais"], hop["ip"] is not None and pasar_a_ms(hop["rtt"]) or "Unknown", hop["ttl"])
        print temp
        caminofile.write(temp+"\n")

with open(hostname + "_saltos.csv", "w+") as saltosfile:
    titulo = "Saltos:\n---------------"
    header = "{0:^25s} -> {1:^25s}\t{2}".format('Origen', 'Destino', 'RTTs relativos')
    saltosfile.write(titulo+"\n")
    saltosfile.write(header+"\n")
    print "\n" + titulo
    print header
    for x in xrange(len(ip_relativos)):
        marcador = x in outliers and '[outlier]' or ''
        temp = "({4:>2d}) {0:<20s} -> ({5:>2d}) {1:<20s}\t{2}\t{3}".format(obtener_pais(ip_relativos[x][0]),
            obtener_pais(ip_relativos[x][1]),
            pasar_a_ms(rtt_relativos[x]),
            marcador,
            saltos[x][0],
            saltos[x][1]
        )
        print temp
        saltosfile.write(temp+"\n")
