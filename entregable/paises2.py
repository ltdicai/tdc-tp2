import urllib2
import json

#URL = "http://freegeoip.net/json/"
URL = "http://api.db-ip.com/v2/ffd8655a7e7c47353c16b0f78c883a0f8f4ba4b4/"

def obtener_pais(ip):
    if ip is None:
        return 'Unknown'

    ip = str(ip).strip()

    if ip.find('192.168.') == 0 or ip.find('10.') == 0:
        return 'Red local'

    try:
        response = urllib2.urlopen(URL + ip)
        res_json = json.load(response)
        country_name = str(res_json["countryName"])
        return country_name
    except Exception, exc:
        return 'Unknown'
