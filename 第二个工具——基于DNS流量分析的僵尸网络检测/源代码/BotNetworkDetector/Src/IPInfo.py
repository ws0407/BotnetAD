import geoip2.database


class IPDetails:
    def __init__(self, ip):
        try:
            self.ip = ip
            self.reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            self.city_name = ""
            self.sub_name = ""
            self.country_name = ""
            response = self.reader.city(self.ip)
            # print response.country.iso_code
            self.country_name = response.country.name
            self.sub_name = response.subdivisions.most_specific.name
            # print response.subdivisions.most_specific.iso_code
            self.city_name = response.city.name
            # print response.postal.code
            # print response.location.latitude
            # print response.location.longitude
            self.reader.close()

        except:
            self.city_name = ""
            self.sub_name = ""
            self.country_name = ""

