from urllib2 import urlopen

#URL = "http://freegeoip.net/json/"
URL = "http://api.db-ip.com/v2/ffd8655a7e7c47353c16b0f78c883a0f8f4ba4b4/"

def cargar(filename, cache):
    try:
        with open(filename, "r") as csvfile:
            for linea in csvfile:
                (ip, pais) = linea.split(",")
                cache[ip] = pais.strip()
    except IOError:
        pass


def obtener_pais(ip, cache):
    if ip is None:
        return None
        
    if not cache:
        cargar("archivo.csv", cache)

    ip = str(ip).strip()

    if ip in cache:
        return cache[ip]
    else:
        for intento in xrange(3):
            try:
                response = urlopen(URL + str(ip), None, 3)
                res_json = json.load(response)
                print response
                print res_json
                country_name = str(res_json["countryName"])
                if not country_name:
                    continue
                with open("archivo.csv", "a") as csvfile:
                    csvfile.write("{0},{1}\n".format(ip, country_name))
                cache[ip] = country_name
                return country_name
            except Exception, exc:
                continue
        return None
