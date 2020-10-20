import platform
import subprocess
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.message
import dns.dnssec
import socket
import nmap3
import simplejson as json
from pygments import highlight, lexers, formatters
import dns.rdatatype
import dns.flags

class bcolor:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    WHITE  = '\033[97m'

class NmapScan:
    state = ""
    os = ""
    def __init__(self, ip):
        n = nmap3.Nmap()
        result = n.nmap_os_detection(ip)
        for data in result:
            self.os = data['cpe']

class DnsChecker:
    domain = ""
    ip = ""
    ns = []
    txt = []
    soa = ""
    mx = ""
    timeout = 5.0
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

    def get_general_info(self):
        try:
            print(bcolor.RED +  "********** Información General *******************" + bcolor.GREEN)
            print(bcolor.YELLOW + "Dominio : " + bcolor.WHITE + self.domain)
            print(bcolor.YELLOW + "IP : " + bcolor.WHITE + self.ip)
            for index in self.ns:
                print(bcolor.YELLOW + "NameServer: " + bcolor.WHITE + index)
            for index in self.txt:
                print(bcolor.YELLOW + "TXT record: " + bcolor.WHITE + index)
            print(bcolor.YELLOW + "SOA (Start of authority) : " + bcolor.WHITE + self.soa)
            print(bcolor.YELLOW + "MX (Mail Server): " + bcolor.WHITE + self.mx)

        except Exception as e:
            print(e)

    def query_response_time(self):
        answer = ""
        try:
            query = dns.message.make_query(self.domain, dns.rdatatype.DS, dns.rdataclass.IN)
            query.flags += dns.flags.CD
            query.use_edns(edns=True, payload=4096)
            print(bcolor.YELLOW + "DNSSEC : " + str(query.want_dnssec(True)))

            print(bcolor.RED + "************Validación de disponibilidad de server DNS **************" + bcolor.GREEN)
            i=1
            for data in self.ns:
                print(bcolor.RED + "************ DNS Sever # {0} **************".format(i) + bcolor.GREEN)
                answer = dns.query.udp(query, socket.gethostbyname(data), self.timeout)
                print(bcolor.YELLOW + "Server: " + bcolor.WHITE + format(data) + bcolor.YELLOW + " IP : " + bcolor.WHITE + socket.gethostbyname(data) + bcolor.YELLOW + " Estado : " +  bcolor.WHITE + "Operativo" )
                print(bcolor.YELLOW + "Timeout : " + bcolor.WHITE)
                self.ping(socket.gethostbyname(data))
                print(bcolor.YELLOW + "Tamaño de carga util EDNS (payload) : " + bcolor.WHITE + str(answer.payload))
                print(bcolor.YELLOW + "Flags del mensaje: " + bcolor.WHITE + str(answer.flags))
                scan = NmapScan(str(socket.gethostbyname(data)))
                print("Sistema Operativo : " + scan.os)
                self.transfer_zone(socket.gethostbyname(data))
                i += 1
        except dns.exception.Timeout:
            print(bcolor.RED + " Advertencia!! -> Tiempo de espera superado al tratar de llegar al servidor DNS en {0} segundos ".format(self.timeout))
        except Exception as e:
            raise

    def print_data(self):
        self.get_general_info()
        self.query_response_time()

    def transfer_zone(self, ip):
        try:
            print (bcolor.RED + "######## Zones Transference #######################" + bcolor.GREEN)
            #z = dns.zone.from_xfr(dns.query.xfr("81.4.108.41","zonetransfer.me"))
            zone = dns.zone.from_xfr(dns.query.xfr(ip,self.domain))
            names = zone.nodes.keys()
            print ("Zona de Transferencia Activada....... A continuación la lista encontrada")
            for n in names:
                print(zone[n].to_text(n))
        except dns.xfr.TransferError:
            print ("Transferencia de Zona para el dominio {0} no esta autorizada ".format(self.domain))

    def ping(self, ip):
         param = '-n' if platform.system().lower()=='windows' else '-c'
         command = ['ping', param, '1', ip]
         return subprocess.call(command) == 0

if __name__ == '__main__':
    #domain = "prueba.com"
    domain = input ("Ingrese el dominio a evaluar: ")
    try:
        obj = DnsChecker(domain)
        obj.print_data()
    except socket.gaierror:
        print (bcolor.RED + " Advertencia: Dominio no existe !!")
