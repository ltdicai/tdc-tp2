# -*- coding: utf-8 -*-
import time
import argparse
from geoip2.database import Reader
from math import *
from scapy.all import *
from scapy.config import conf
from modified_thompson import thompson_tau_test
from collections import defaultdict
from utiles import *
from paises2 import *


######## Para correr Script: sudo python traceroute_estimatedRtt_n_zrtt.py 'ip' ########
######## Ejemplo:  sudo python traceroute_estimatedRtt_n_zrtt.py 23.12.153.99   ########

#Constantes
ECHO_REPLY = 0


rtt_por_hop = defaultdict(list)
cache_paises = dict()

try:
    country_database = Reader("GeoLite2-Country.mmdb")
except:
    country_database = None



def rastrear(hostname, max_ttl, tam_rafaga, timeout, ptimeout):
    t_t_inicio = time.time()
    muestras = dict()
    destino_alcanzado = False
    for ttl in xrange(1, max_ttl+1):
        if destino_alcanzado:
            break
        muestras[ttl] = defaultdict(list)
        pkt = IP(dst=hostname, ttl=ttl) / ICMP()/"XXXXXXXdddfXXXX"
        reply = None
        fallos = 0
        for i in xrange(tam_rafaga):
            print "TTL: {0:>3d} | #PKT: {1:>3d}".format(ttl, i)
            t_inicio = time.time()
            reply = sr1(pkt, verbose=0, timeout=timeout)
            t_final = time.time() - t_inicio
            if reply:
                fallos = 0
                muestras[ttl][str(reply.src)].append(t_final)
                if reply.type == ECHO_REPLY:
                    destino_alcanzado = True
            else:
                muestras[ttl][None].append(t_final)
                fallos += 1
                if fallos > ptimeout * tam_rafaga:
                    break
    t_t_final = time.time() - t_t_inicio

    print "Se completó el rastreo en {0} segundos".format(t_t_final)

    muestreo = dict()
    for ttl, respuestas in muestras.items():
        muestreo[ttl] = list()
        for ip, rtts in respuestas.items():
            if ip is not None:
                outliers = set(thompson_tau_test(rtts))
                rtts_filt = [item for idx, item in enumerate(rtts) if idx not in outliers]
                muestreo[ttl].append({
                    'ip': ip,
                    'ttl': ttl,
                    'cant_respuestas': len(rtts),
                    'rtts':rtts,
                    'rtt_minimo': minimo(rtts),
                    'rtt_promedio': promedio(rtts),
                    'rtt_mediana': mediana(rtts),
                    'rtts_filt': rtts_filt,
                    'rtt_filt_promedio': promedio(rtts_filt)
                })
            else:
                muestreo[ttl].append({
                    'ip': None,
                    'ttl': ttl,
                    'cant_respuestas': len(rtts),
                    'rtts':rtts,
                    'rtt_minimo': None,
                    'rtt_promedio': None,
                    'rtt_mediana': None,
                    'rtts_filt': None,
                    'rtt_filt_promedio': None
                })
    return muestreo

def obtener_pais(ip):
    if ip is None or country_database is None:
        return "Unknown"
    if ip.startswith("10.") or ip.startswith("192.168."):
        return "Local"
    try:
        response = country_database.country(ip.strip())
        if response.country.name:
            return response.country.name
        else:
            return response.continent.name
    except Exception, exc:
        print exc
        return "Unknown"

def cuerpo(hostname, max_ttl, tam_rafaga, timeout, ptimeout, output_file_name):
    muestreo = rastrear(hostname, max_ttl, tam_rafaga, timeout, ptimeout)
    #print muestreo

    #Generamos el camino estimado, usando para cada TTL el nodo
    #que devolvio mas respuestas
    camino = list()
    for ttl, respuestas in muestreo.items():
        mejor = respuestas[0]
        for respuesta in respuestas:
            if respuesta["ip"] is not None and respuesta['cant_respuestas'] > mejor['cant_respuestas']:
                mejor = respuesta
        camino.append(mejor)

    #Completamos el pais correspondiente a cada host del camino
    for host in camino:
    #    host['pais'] = 'Unknown'
    #    host['pais'] = obtener_pais(host['ip'], cache_paises)
        print 'buscando pais de ' + str(host['ip'])
        host['pais'] = obtener_pais(host['ip'])


    saltos = list()
    camino_solo_respuestas = [item for item in camino if item["ip"] is not None]
    for i in xrange(1, len(camino_solo_respuestas)):
        origen = camino_solo_respuestas[i-1]
        destino = camino_solo_respuestas[i]

        saltos.append({
            'origen': origen,
            'destino': destino,
            'minimo': {
                'valor': abs(destino["rtt_minimo"] - origen["rtt_minimo"]),
                'outlier': False
            },
            'promedio': {
                'valor': abs(destino["rtt_promedio"] - origen["rtt_promedio"]),
                'outlier': False
            },
            'mediana': {
                'valor': abs(destino["rtt_mediana"] - origen["rtt_mediana"]),
                'outlier': False
            },
            'filt_promedio': {
                'valor': abs(destino["rtt_filt_promedio"] - origen["rtt_filt_promedio"]),
                'outlier': False
            },
        })

    #Marcamos los outliers
    for i in thompson_tau_test([salto['minimo']['valor'] for salto in saltos]):
        saltos[i]['minimo']['outlier'] = True

    for i in thompson_tau_test([salto['promedio']['valor'] for salto in saltos]):
            saltos[i]['promedio']['outlier'] = True

    for i in  thompson_tau_test([salto['filt_promedio']['valor'] for salto in saltos]):
        saltos[i]['filt_promedio']['outlier'] = True

    for i in thompson_tau_test([salto['mediana']['valor'] for salto in saltos]):
        saltos[i]['mediana']['outlier'] = True

    #Outputs
    print "Guardando archivo de muestras"
    with open(output_file_name + "_muestreo.txt", "w+") as muestreofile:
        muestreofile.write("Muestreo\n")
        for ttl, respuestas in muestreo.items():
            temp = { ttl: respuestas }
            #print temp
            muestreofile.write(str(temp)+"\n")

    print "Guardando archivo de camino"
    with open(output_file_name + "_camino.txt", "w+") as caminofile:
        titulo = "Camino:\n---------------"
        header = "{0:>2}\t{1:^20s}\t{2:^20s}\t{3:^20s}\t{4:^20s}\t{5:^20s}\t{6:^20s}".format(
            'TTL', 'IP', 'Pais', 'RTT Minimo' ,'RTT Promedio', 'RTT Filtrado Prom', 'RTT Mediana' )
        caminofile.write(titulo + "\n" + header + "\n")
        print "\n" + titulo + "\n" + header
        for hop in camino:
            temp =  "{0:>2}\t{1:<20s}\t{2:^20s}\t{3:^20s}\t{4:^20s}\t{5:^20s}\t{6:^20s}".format(
                hop["ttl"],
                hop["ip"],
                hop["pais"],
                hop["ip"] is not None and pasar_a_ms(hop["rtt_minimo"]) or "Unknown",
                hop["ip"] is not None and pasar_a_ms(hop["rtt_promedio"]) or "Unknown",
                hop["ip"] is not None and pasar_a_ms(hop["rtt_filt_promedio"]) or "Unknown",
                hop["ip"] is not None and pasar_a_ms(hop["rtt_mediana"]) or "Unknown"
                )
            print temp
            caminofile.write(temp+"\n")

    print "Guardando archivo de saltos"
    with open(output_file_name + "_saltos.txt", "w+") as saltosfile:
        titulo = "Saltos:\n---------------"
        header = "{0:^25s} -> {1:^20s}\t{2:^20s}\t{3:^20s}\t{4:^20s}\t{5:^20s}".format(
            'Origen', 'Destino', 'Minimo', 'Promedio', 'Promedio Filtrado', 'Mediana')
        saltosfile.write(titulo+"\n"+header+"\n")
        print "\n" + titulo
        print header
        for salto in saltos:
            temp = "({0:>2d}) {1:<20s} -> ({2:>2d}) {3:<20s}\t{4:^20s}\t{5:^20s}\t{6:^20s}\t{7:^20s}".format(
                salto['origen']['ttl'],
                salto['origen']['pais'],
                salto['destino']['ttl'],
                salto['destino']['pais'],
                (salto['minimo']['outlier'] and '[' or '') + pasar_a_ms(salto['minimo']['valor']) + (salto['minimo']['outlier'] and ']' or ''),
                (salto['promedio']['outlier'] and '[' or '') + pasar_a_ms(salto['promedio']['valor']) + (salto['promedio']['outlier'] and ']' or ''),
                (salto['filt_promedio']['outlier'] and '[' or '') + pasar_a_ms(salto['filt_promedio']['valor']) + (salto['filt_promedio']['outlier'] and ']' or ''),
                (salto['mediana']['outlier'] and '[' or '') + pasar_a_ms(salto['mediana']['valor']) + (salto['mediana']['outlier'] and ']' or '')
            )
            print temp
            saltosfile.write(temp+"\n")


################################################################################
def main(argv):
    parser = argparse.ArgumentParser(description='Traceroute con protocolo ICMP')
    parser.add_argument(
        'host', metavar='host', type=str,
        help='URL o IP del host destino.'
    )
    parser.add_argument(
        "--max_hop", "-mh", type=int, default=30,
        help=u"Cantidad maxima de saltos."
    )
    parser.add_argument(
        "--tam_rafaga", "-tr", type=int, default="5",
        help=u"Cantidad de paquetes que se envian para un mismo TTL."
    )
    parser.add_argument(
        "--timeout", "-t", type=float, default=2,
        help=u"Tiempo de espera antes de decidir que un nodo no responde."
    )
    parser.add_argument(
        "--ptimeout", "-p", type=float, default=0.1,
        help=u"Valor entre 0 y 1. Porcentaje de envíos con timeout (en seguidilla) necesario para deducir que un hop no responde, y continuar con el siguiente hop."
    )
    parser.add_argument(
        "--output", "-o", type=str, default="",
        help=u"Tiempo de espera antes de decidir que un nodo no responde."
    )

    args = parser.parse_args(argv[1:])
    if args.output == '':
        args.output = args.host
    cuerpo(args.host, args.max_hop, args.tam_rafaga, args.timeout, args.ptimeout, args.output)

if __name__ == '__main__':
    try:
        if os.geteuid():
            print u"Tenés que correrlo con sudo"
            sys.exit(1)
    except (OSError, AttributeError):
        pass
main(sys.argv)
