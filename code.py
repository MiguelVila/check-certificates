import ssl
import socket
from datetime import datetime
import OpenSSL
import sys

def get_cert_info(domain):
    try:
        # Establece una conexión SSL sin validar el certificado
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain,
        )
        conn.settimeout(10)
        conn.connect((domain, 443))

        # Obtén el certificado del servidor
        cert = conn.getpeercert(True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

        # Extrae las fechas de firmado y expiración
        start_date = datetime.strptime(x509.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ")
        end_date = datetime.strptime(x509.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")

        # Extrae el día, mes y año por separado
        start_day = start_date.day
        start_month = start_date.month
        start_year = start_date.year

        end_day = end_date.day
        end_month = end_date.month
        end_year = end_date.year

        # Extrae el CN del subject
        subject = x509.get_subject().commonName

        # Extrae el issuer y obtén solo el CN
        issuer = x509.get_issuer().commonName
        issuer_cn = issuer.split('=')[-1]

        return (domain, start_day, start_month, start_year, end_day, end_month, end_year, issuer_cn, subject)
    except Exception as e:
        return (domain, None, None, None, None, None, None, None, None, str(e))

def main(filename):
    with open(filename, 'r') as f:
        domains = f.read().splitlines()

    results = []
    for domain in domains:
        info = get_cert_info(domain)
        results.append(info)
        print(info)

    # Guarda los resultados en un archivo
    with open('certificates_info.txt', 'w') as f:
        for result in results:
            if all(result[1:9]):  # Check if all date parts, issuer and subject are not None
                f.write(f"{result[0]}: start_date={result[1]:02d}-{result[2]:02d}-{result[3]}, end_date={result[4]:02d}-{result[5]:02d}-{result[6]}, issuer_CN={result[7]}, subject_CN={result[8]}\n")
            else:
                f.write(f"{result[0]}: Error: {result[9]}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python script.py <archivo_de_dominios>")
        sys.exit(1)
    
    filename = sys.argv[1]
    main(filename)
