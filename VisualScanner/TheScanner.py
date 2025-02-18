from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def print_devices(devices):
    print("Dispositivos na rede:")
    print("IP" + " "*18+"MAC")
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))

if __name__ == "__main__":
    ip_range = "192.168.1.1/24"  # Substitua pelo range de IP da sua rede
    devices = scan_network(ip_range)
    print_devices(devices)
