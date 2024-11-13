import nmap

def scan_firewall(ip_address):
    # Inisialisasi scanner nmap
    scanner = nmap.PortScanner()

    # Lakukan scanning dengan beberapa opsi untuk deteksi firewall
    print(f"Scanning IP {ip_address} for firewall detection...\n")
    scanner.scan(ip_address, arguments="-sA -p 80,443,22,21,8080,53")

    # Cek hasil scan
    for proto in scanner[ip_address].all_protocols():
        print(f"Protocol: {proto}")
        lport = scanner[ip_address][proto].keys()
        for port in lport:
            state = scanner[ip_address][proto][port]['state']
            print(f"Port: {port}\tState: {state}")

    # Analisa apakah firewall ganas atau tidak
    if "filtered" in [scanner[ip_address][proto][port]['state'] for proto in scanner[ip_address].all_protocols() for port in scanner[ip_address][proto]]:
        print("\nFirewall Detected: Agressive Firewall is likely active.")
    else:
        print("\nNo Firewall Detected or Firewall is not blocking aggressively.")

# Masukkan IP atau domain yang ingin discan
ip_to_scan = input("Enter IP or domain to scan for firewall detection: ")
scan_firewall(ip_to_scan)
