import asyncio
import concurrent.futures
import socket
import netifaces
import ipaddress

class IPDiscoveryError(Exception):
    pass

def getActiveIPAddress() -> ipaddress.ip_address:
    #TODO: Add capabilities to handle IPv6
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(('10.255.255.255', 1))
            return ipaddress.ip_address(s.getsockname()[0])
        except OSError:
            return 0

def interfacesOfType(ipVersion: int) -> list:
    return [gateway[1] for gateway in netifaces.gateways()[ipVersion]]

def getNetmask(addressInfo: dict) -> ipaddress.ip_address:
    #netifaces has an odd feature where, if the subnet mask is 255.255.255.0, it will
    #sometimes not return any value for 'netmask' in the address information
    if 'netmask' in addressInfo:
        return ipaddress.ip_address(addressInfo["netmask"])
    else:
        return ipaddress.ip_address("255.255.255.0")
    
def getHostMask(netMask: ipaddress.ip_address, ip: ipaddress.ip_address) -> ipaddress.ip_address:
    return ipaddress.ip_address(int(ip) & int(netMask))

def addressesInInterface(interfaceName: str, ipVersion: int) -> list:
    return netifaces.ifaddresses(interfaceName)[ipVersion]

def addressesOfIPType(ipVersion: int) -> list():
    addresses = []
    for interface in interfacesOfType(ipVersion):
        for address in addressesInInterface(interface, ipVersion):
            addresses.append(address)
    return addresses

def networksOfIPType(ipVersion: int) -> list():
    pairs = []
    for address in addressesOfIPType(ipVersion):
        netMask = getNetmask(address)
        hostMask = getHostMask(netMask, ipaddress.ip_address(address["addr"]))
        pairs.append(ipaddress.ip_network(f"{hostMask}/{netMask}"))
    return pairs

def getIPVersion(ip: ipaddress.ip_address) -> int:
    if ip.version == 4:
        return netifaces.AF_INET
    elif ip.version == 6:
        return netifaces.AF_INET6
    else:
        return 0

def findNetworkIPIsOn(ip: ipaddress.ip_address) -> ipaddress.ip_network:
    networks = networksOfIPType(getIPVersion(ip))
    for network in networks:
        if ip in network:
            return network
    raise IPDiscoveryError(f"Could not find valid network for IP {ip}")

async def openConnection(address: ipaddress.ip_address, port: int):
    return await asyncio.open_connection(str(address), port)
        
async def isSocketListening(address: ipaddress.ip_address, port: int) -> tuple:
    listening = True
    try:
        reader, writer = await asyncio.wait_for(openConnection(address, port), timeout=0.1)
    except (socket.gaierror, concurrent.futures._base.TimeoutError) as error:
        listening = False
    except OSError:
        listening = False
    else:        
        writer.close()
        await writer.wait_closed()
        return (address, listening)
    
async def findListeningSocket(network: ipaddress.ip_network, port: int) -> list:
    while True:
        pings = []
        for ip in network:
            pings.append(isSocketListening(ip, port))
        yield [result[0] for result in await asyncio.gather(*pings) if result]

async def findIPsListeningOnPort(port: int) -> list:
    ipAddress = getActiveIPAddress()
    if ipAddress == 0:
        raise IPDiscoveryError("Unable to find IP Address")
    
    network = findNetworkIPIsOn(getActiveIPAddress())
    networkScanner= findListeningSocket(network, port)
    
    while True:
        async for addressList in networkScanner:
            keepScanning = yield addressList
            if keepScanning == False:
                await networkScanner.aclose()
                yield

if __name__ == '__main__':
    def getPort(message: str = "Which port should be scanned for? ") -> int:
        try:
            port = int(input(message))
            if 1 <= port <= 65535:
                return port
            else:
                raise ValueError
        except ValueError:
            getPort("Please enter a valid port number\n")

    async def scanNetwork():
        try:
            port = getPort()
            scanner = findIPsListeningOnPort(port)
            async for ip in scanner:
                print(ip)
                if input("Keep Scanning [y/n]? ") == "n":
                    await scanner.asend(False)
                    await scanner.aclose()
        except IPDiscoveryError as ipde:
            print(f"Error : {ipde}. Please check your internet connection")

    asyncio.run(scanNetwork())
