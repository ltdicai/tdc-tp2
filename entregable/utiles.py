from geoip2.database import Reader

def mediana(lst):
    sortedLst = sorted(lst)
    lstLen = len(lst)
    index = (lstLen - 1) // 2

    if (lstLen % 2):
        return sortedLst[index]
    else:
        return (sortedLst[index] + sortedLst[index + 1])/2.0

def promedio(lst):
    if len(lst) > 0:
        return sum(lst)/len(lst)
    else:
        return 0

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

def minimo(lst):
    min = None
    if len(lst) > 0:
        min = lst[0]
        for i in range(0, len(lst)):
            if lst[i] < min:
                min = lst[i]
    return min


def obtener_pais(ip):
    try:
        country_database = Reader("GeoLite2-Country.mmdb")
    except:
        country_database = None

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
