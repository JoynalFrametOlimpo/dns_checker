import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.message
import socket


import dns.rdatatype
import dns.flags

class bcolor:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    WHITE  = ''\033[97m'


class DnsChecker:

    domain = ""
    ip = ""
    ns = []
    txt = []
    soa = ""
    mx = ""
    timeout = 0.8
    def banner(self):
        flag = """
          =======================================================================================================
          *       ********     ******     **       **   **         **     ******    **           '``'           *
          *          **       **    **     **     **    ** **      **   **     **   **          '- framet'?''   *
          *          **       **    **      **   **     **  **     **   **     **   **            ''    ''      *
          *          **       **    **       ** **      **    **   **   *********   **                          *
          *          **       **    **        ***       **     **  **   **     **   **                          *
          *     **   **       **    **         **       **      *****   **     **   **       **                 *
          *      *****         ******          **       **        ***   **     **   ***********                 *
          =======================================================================================================
            """
        print(bcolor.GREEN + flag)

    def __init__(self, domain):
        self.domain = domain
        self.get_ip()
        self.get_ns()
        self.get_txt()
        self.get_soa()
        self.get_mx()
        self.banner()

    def get_ip(self):
        try:
            result = dns.resolver.resolve(self.domain, 'A')
            for data in result:
                self.ip = data.to_text()
        except Exception as e:
            print( "No se pudo resolver la ip del dominio : " + self.domain)

    def get_ns(self):
        try:
            result = dns.resolver.resolve(self.domain, 'NS')
            for data in result:
                self.ns.append(data.to_text())
            self.ns.sort()
        except Exception as e:
            print( "No se pudo resolver los names server del dominio : " + self.domain)

    def get_txt(self):
        try:
            result = dns.resolver.resolve(self.domain, 'TXT')
            for data in result:
                self.txt.append(data.to_text())
        except Exception as e:
            print ("No se puede resolver TXT record del domain : " + self.domain)

    def get_soa(self):
        try:
            result = dns.resolver.resolve(self.domain, 'SOA')
            for data in result:
                self.soa = data.to_text()
        except Exception as e:
            print( "No se pudo resolver SOA (Start of authority) del dominio : " + self.domain)

    def get_mx(self):
        try:
            result = dns.resolver.resolve(self.domain, 'SOA')
            for data in result:
                self.mx = data.to_text()
        except Exception as e:
            print( "No se pudo resolver MX (Mail Server for accepting email messages) del dominio : " + self.domain)

    def query_response_time(self):
        answer = ""
        try:
            query = dns.message.make_query(self.domain, dns.rdatatype.DS, dns.rdataclass.IN)
            query.flags += dns.flags.CD
            query.use_edns(edns=True, payload=4096)
            query.want_dnssec(True)

            print(bcolor.RED + "************Validación de disponibilidad de server DNS **************" + bcolor.GREEN)
            for data in self.ns:
                answer = dns.query.udp(query, socket.gethostbyname(data), self.timeout)
                print("Server {0} ".format(data) + socket.gethostbyname(data))
                print("Tamaño de carga util EDNS (payload) : " + str(answer.payload))
                print("Flags del mensaje: " + str(answer.flags))
        except dns.exception.Timeout:
            print("Tiempo de espera superado al tratar de llegar al servidor DNS en {0} segundos ".format(self.timeout))
        except Exception as e:
            raise


    def print_data(self):
        print(bcolor.RED +  "********** Información General *******************" + bcolor.GREEN)
        print("Dominio : " + self.domain)
        print("IP : " + self.ip)
        for index in self.ns:
            print("NameServer: " + index)
        for index in self.txt:
            print("TXT record: " + index)
        print("SOA (Start of authority) : " + self.soa)
        print("MX (Mail Server): " + self.mx)
        self.query_response_time()


    def get_dns_zone(domain):
        try:
            print (bcolor.RED + "######## Zones Transference #######################" + bcolor.GREEN)
            print (dns.query.xfr("178.238.238.235","ns1.contabo.net"))
            z = dns.zone.from_xfr(dns.query.xfr(domain,"ns1.contabo.net"))
            print (z)
            names = z.nodes.keys()
            names.sort()
            for n in names:
                print(z[n].to_text(n))
        except Exception as e:
            print (e)

    def get_property(domain):
        print("#########  PROPERTY ##############")
        print(dns.name.from_text(domain))
        print(dns.name.from_unicode(domain))



if __name__ == '__main__':
    domain = "ticgobi.com"
    obj = DnsChecker(domain)

    obj.print_data()
    #get_dns_data(domain)
    #get_property(domain)
    #gt_dns_zone(domain)

    #domain = input ("Ingrese el dominio a evaluar: ")
    #get_dns_data(str(domain))
