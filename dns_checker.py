import dns.resolver
import dns.reversename

def get_dns_data(domain):
    file = open("param","r")
    param = file.read().split("\n")
    param = param[:-1]

    for x in param:
        try:
            text = dns.resolver.resolve(domain, str(x))
            for data in text:
                print ("Valor " + x + " es = ", ":", data.to_text())
        except Exception as e:
            print (e)

def get_property(domain):
    print("#########  PROPERTY ##############")
    print(dns.name.from_text(domain))
    print(dns.name.from_unicode(domain))


if __name__ == '__main__':
    domain = "ticgobi.com"
    get_dns_data(domain)
    get_property(domain)

    #domain = input ("Ingrese el dominio a evaluar: ")
    #get_dns_data(str(domain))
