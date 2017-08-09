#!/usr/bin/env python
# -*- coding: utf-8 -*-​
__version__ = '0.2'

import fcntl
import sys, os, time
import base64
from datetime import datetime
from random import randint
from platform import system
from threading import Thread, Lock
import logging, time, socket
from subprocess import Popen, PIPE
from signal import SIGINT
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# user defined variables
verbose = 1  ## verbosity level (0-3)
interfaces = ['wlan1']  ## Wi-Fi interface/s ['wlan1','wlan2']
channel = 3  ## Channel to use by default
apsecurity = 'OPEN'  ## open, wep, wpa, wpa2
ssid = 'CTF!!!'  ## default SSID to use
count = 100  ## Default number of packets to send
gpioled = '5'
gpiosend = ''
gpiodisarm = '7'
gpioarm = '4'
ctftime=3600  ## Default CTF duration in seconds
countdownscreen=0 ## If 1 it will display a countdown full screen

# system variables
src = RandMAC()  ## source ip from packets
dst = 'ff:ff:ff:ff:ff:ff'  ## Destination address for beacons and probes
broadcast = 'ff:ff:ff:ff:ff:ff'  ## Destination address for beacons and probes
sc = randint(1, 4096)
payload = ''
frequency = ''
gpiobase = '/sys/class/gpio'
monifaces = list()
lock = Lock()
DN = open(os.devnull, 'w')
numifaces = len(interfaces)
payload_ie=221  ## 802.11 Element ID to include payload
payload_preffix='CTF'  ## When using element ID 221 the first 3 bytes are for the manuf OUI

# Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']


class gpio(Thread):
    def __init__(self, gpio, direction, action='none'):
        Thread.__init__(self)
        Thread.daemon = True
        self.gpio = str(gpio)
        self.direction = direction
        self.status = 0
	self.action = action
        if gpio and self.testgpio():
            self.status = 1
            self.initpin()
            self.ioconfig()

    def run(self):
	if self.action == 'blink':
	    self.blink(100,1)
	if self.action == 'read':
	    self.read(1,1)
	else:
	    return

    def testgpio(self):
        try:
            f = open('{0}/unexport'.format(gpiobase), 'w')
            f.write(self.gpio)
            f.close()
            return True
        except IOError as e:
            logging.error('Invalid GPIO port: %s' % self.gpio)
            return False

    def initpin(self):
        f = open('{0}/export'.format(gpiobase), 'w')
        f.write(self.gpio)
        f.close()
        logging.debug("Initialized GPIO port: %s" % self.gpio)

    def ioconfig(self):
        port = '{0}/gpio{1}/direction'.format(gpiobase, self.gpio)
        f = open(port, 'w')
        f.write(self.direction)
        f.close()

    def led(self, action):
        port = '{0}/gpio{1}/value'.format(gpiobase, self.gpio)
        f = open(port, 'w')
        f.write(str(action))
        f.close()

    def act(self,val,time):
        port = '{0}/gpio{1}/value'.format(gpiobase, self.gpio)
        f = open(port, 'w')
        f.write(val)
        f.close()
        time.sleep(int(time))
        f = open(port, 'w')
        f.write(str(not int(val)))
        f.close()

    def blink(self, times, period):
        i = 0
        port = '{0}/gpio{1}/value'.format(gpiobase, self.gpio)
        while i < int(times):
            f = open(port, 'w')
            f.write('1')
            f.close()
            time.sleep(period)
            f = open(port, 'w')
            f.write('0')
            f.close()
            time.sleep(period)
            i += 1

    def timecheck(self):
        port = '{0}/gpio{1}/value'.format(gpiobase, self.gpio)
        while 1:
	    if timeleft() < 1:
		print "CTF Remaining time elapsed! Time left: %" %timeformat(timeleft())
		self.act(1,5)
		break
	    time.sleep(1)

    def read(self, times, period):
        port = '{0}/gpio{1}/value'.format(gpiobase, self.gpio)
        while 1:
            elapsed = 0
            pushed = 0
            f = open(port, 'r')
            if int(f.read):  ## reads 1: pressed
                pushed = 1
                f = open(port, 'r')
                while elapsed < int(period):
                    if not int(f.read()):
                        pushed = 0
                        f.close()
                        break
                    time.sleep(0.2)
                    f.close()
                elapsed += 0.1
            if pushed == times:
                print 'OK'
            time.sleep(0.1)
            f.close()

    def close(self):
        f = open('{0}/unexport'.format(gpiobase), 'w')
        f.write(self.gpio)
        f.close()


def oscheck():
    osversion = system()
    if verbose:
        logging.debug("Operating System: %s" % osversion)
    if osversion != 'Linux':
        logging.debug("This script only works on Linux OS! Exitting!")
        exit(1)


def initmons(intfparent):
    global monifaces, ignore
    i = 0
    logging.debug("Number of interfaces to use: %d %s" % (numifaces, intfparent))
    for interface in intfparent:
        if not os.path.isdir("/sys/class/net/" + interface):
            logging.debug("WiFi parent interface %s does not exist! Cannot continue!" % interface)
            exit(1)
        else:
            interfacemon = 'mon' + str(i)
            i += 1
            if os.path.isdir("/sys/class/net/" + interfacemon):
                logging.debug("WiFi interface %s exists! Deleting it!" % (interfacemon))
                try:
                    # create monitor interface using iw
                    os.system("iw dev %s del" % interfacemon)
                    time.sleep(0.5)
                except OSError as oserr:
                    logging.debug("Could not delete monitor interface %s. %s" % (interfacemon, oserr.message))
                    os.kill(os.getpid(), SIGINT)
                    sys.exit(1)
            try:
                # create monitor interface using iw
                os.system("iw dev %s interface add %s type monitor" % (interface, interfacemon))
                time.sleep(0.5)
                os.system("ifconfig %s up" % interfacemon)
                if verbose:
                    logging.debug("Creating monitor VAP %s for parent %s..." % (interfacemon, interface))
                monifaces.append(interfacemon)
            except OSError as oserr:
                logging.debug("Could not create monitor %s. %s" % (interfacemon, oserr.message))
                os.kill(os.getpid(), SIGINT)
                sys.exit(1)
            # Get actual MAC addresses
            macaddr1 = GetMAC(interface).upper()
            ignore.append(macaddr1)
            if verbose: logging.debug("Actual %s MAC Address: %s" % (interface, macaddr1))
            macaddr = GetMAC(interfacemon).upper()
            if macaddr1 != macaddr:
                ignore.append(macaddr);
                if verbose:
                    logging.debug("Actual %s MAC Address: %s" % (interfacemon, macaddr))


def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac


def calc_freq(channel):
    global frequency
    if channel in range(1, 14):
        if channel == 14:
            frequency = "2484"
        else:
            frequency = str(2407 + (channel * 5))
        return frequency
    else:
        return "n/a"


class Dot11EltRates(Packet):
    name = "802.11 Rates Information Element"
    # Our Test STA supports the rates 6, 9, 12, 18, 24, 36, 48 and 54 Mbps
    supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(index + 1), rate))


def next_sc():
    # type: () -> object
    global sc
    sc = (sc + 1) % 4096
    temp = sc
    return temp * 16  # Fragment number -> right 4 bits


def get_radiotap_header():
    global channel
    radiotap_packet = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
                               notdecoded='\x00\x6c' + frequency + '\xc0\x00\xc0\x01\x00\x00')
    return radiotap_packet


class Scapy80211():
    def __init__(self, intfparent='wlan1', intfmon='mon0'):
        self.intfparent = intfparent
        self.intfmon = intfmon
        conf.iface = self.intfmon

    def beacon(self, src, count, ssid, apsecurity, payload):
        if apsecurity.upper() == 'WEP':
            beacon = Dot11Beacon(cap='ESS+privacy')
            rsn = ''
        elif apsecurity.upper() == 'WPA':
            beacon = Dot11Beacon(cap='ESS+privacy')
            rsn = Dot11Elt(ID='RSNinfo', info=(
                '\x01\x00'  # RSN Version 1
                '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
                '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
                '\x00\x0f\xac\x04'  # AES Cipher
                '\x00\x0f\xac\x02'  # TKIP Cipher
                '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
                '\x00\x0f\xac\x02'  # Pre-Shared Key
                '\x00\x00'))  # RSN Capabilities (no extra capabilities)
        elif apsecurity.upper == 'WPA2':
            beacon = Dot11Beacon(cap='ESS+privacy')
            rsn = Dot11Elt(ID='RSNinfo', info=(
                '\x01\x00'  # RSN Version 1
                '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
                '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
                '\x00\x0f\xac\x04'  # AES Cipher
                '\x00\x0f\xac\x02'  # TKIP Cipher
                '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
                '\x00\x0f\xac\x02'  # Pre-Shared Key
                '\x00\x00'))  # RSN Capabilities (no extra capabilities)
        else:
            rsn = ''
            beacon = Dot11Beacon(cap='ESS')
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        dsset = Dot11Elt(ID='DSset', info='\x01')
        tim = Dot11Elt(ID='TIM', info='\x00\x01\x00\x00')
	eltpayload = Dot11Elt(ID=payload_ie,info=payload_preffix+payload) ## vendor/WPS
        pkt = RadioTap() / Dot11(type=0, subtype=8, addr1=broadcast.upper(), addr2=src, addr3=src, SC=next_sc()) / beacon / essid / rsn / Dot11EltRates() / eltpayload / dsset / tim
        if verbose >= 3: pkt.show()
        if verbose >= 2: print '[*] 802.11 Beacon: SSID=[%s], count=%d' % (ssid, count)
        try:
            if sled.status: sled.led(1)
            sendp(pkt, iface=self.intfmon, count=count, inter=0.100, verbose=0)
            if sled.status: sled.led(0)
        except:
            raise

    def probereq(self, src, count, ssid, dst, payload):
        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        dsset = Dot11Elt(ID='DSset', info=chr(channel))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendor/WPS
        pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=dst, addr2=src, addr3=dst, SC=next_sc()) / param / essid / wps / Dot11EltRates() / eltpayload / dsset
        if verbose >= 3: pkt.show()
        if verbose >= 2: print '[*] 802.11 Probe Request: SSID=[%s], count=%d' % (ssid, count)
        try:
            if sled.status: sled.led(1)
            sendp(pkt, count=count, inter=0.1, verbose=0)
            if sled.status: sled.led(0)
        except:
            raise

    def proberesp(self, src, count, ssid, dst, payload):
        param = Dot11ProbeResp(beacon_interval=0x0064, cap=0x2104)
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        dsset = Dot11Elt(ID='DSset', info=chr(channel))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendor/WPS
        pkt = RadioTap() / Dot11(subtype=5, addr1=src, addr2=dst, addr3=dst, SC=next_sc()) / param / essid / Dot11EltRates() / eltpayload / dsset
        # If we are an RSN network, add RSN data to response
        if security[0:3] == 'WPA':
            probe_response_packet[Dot11ProbeResp].cap = 0x3101
            rsn_info = Dot11Elt(ID='RSNinfo', info=RSN)
            probe_response_packet = probe_response_packet / rsn_info
        try:
            if sled.status: sled.led(1)
            sendp(pkt, count=count, inter=0.1, verbose=0)
            if sled.status: sled.led(0)
        except:
            raise

    def authreq(self, src, dst, count, ssid, apsecurity, payload):
        # authentication with open system
        param = Dot11Auth(algo=0, seqnum=1, status=0)
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendor/WPS
        pkt = RadioTap() / Dot11(subtype=0xb, addr1=dst, addr2=src, addr3=dst, SC=next_sc()) / param / essid / eltpayload
        if sled.status: sled.led(1)
        res = srp(pkt, iface=self.intfmon, count=count, timeout=2)
        if sled.status: sled.led(0)
        if res:
            res.summary()
            print "Got answer from " + res.addr2
        else:
            print "Got no answer from " + dst

    def assocreq(self, src, dst, count, ssid, apsecurity, payload):
        # association request
        param = Dot11AssoReq()
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendor/WPS
        pkt = RadioTap() / Dot11(type=0, subtype=0, addr1=dst, addr2=src, addr3=dst,
                                 SC=next_sc()) / param / essid / Dot11EltRates() / eltpayload
        if sled.status: sled.led(1)
        res = srp(pkt, iface=self.intfmon, count=count, timeout=2)
        if sled.status: sled.led(0)
        if res:
            print "Got answer from " + res.addr2
        else:
            print "Got no answer from " + ssid

    def deauth(self, src, dst, count, ssid, payload):
        # Deauthentication request
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendor/WPS
        param = Dot11Deauth() / eltpayload
        pkt = RadioTap() / Dot11(addr1=src, addr2=dst, addr3=dst, SC=next_sc()) / param  ## AP to STA deauth
        pkt2 = RadioTap() / Dot11(addr1=dst, addr2=src, addr3=dst, SC=next_sc()) / param  ## STA to AP deauth
        res = srp1(pkt, retry=5, iface=self.intfmon, timeout=2)
        if res:
            print "Got answer from " + res.addr2
        else:
            print "Got no answer from Station: " + str(src)
        if sled.status: sled.led(1)
        res = srp(pkt2, count=count, iface=self.intfmon, timeout=2)
        if sled.status: sled.led(0)
        if res:
            print "Got answer from " + res.addr2
        else:
            print "Got no answer from AP: " + dst

    # Dot11AssoResp : 802.11 Association Response
    # Dot11Disas : 802.11 Disassociation
    # Dot11ReassoReq : 802.11 Reassociation Request
    # Dot11ReassoResp : 802.11 Reassociation Response
    # Data packets...

    def setchannel(self, chan):
        global channel,frequency
        channel = int(chan)
        frequency = calc_freq(channel)
        try:
            proc = Popen(['iw', 'dev', self.intfmon, 'set', 'channel', str(channel)], stdout=DN, stderr=PIPE)
            if verbose: logging.debug("Setting %s to channel: %s (%s MHz)" % (self.intfmon, channel, frequency))
        except OSError as e:
            logging.debug('Could not execute iw!')
            os.kill(os.getpid(), SIGINT)
            return False
        for line in proc.communicate()[1].split('\n'):
            if len(line) > 2:  # iw dev shouldnt display output unless there's an error
                logging.debug("Error setting channel %s for %s" % (channel, self.intfmon))
                return False


def executecommand(command, value):
    global count, src, dst, ssid, channel, apsecurity, payload
    try:
        if command == "slp":
            print '[%s] Sleeping %s seconds...' %(timeformat(timeleft()),value)
            time.sleep(int(value))
            sys.stdout.write("\033[F")  # Cursor up one line
        if command == "wai":
            wait=ctfstart+(int(value)*60)-int(time.time())
	    if wait < 0:
		wait=1
            print '[%s] Sleeping %d seconds until %s minutes from CTF Start...' %(timeformat(timeleft()),wait,value)
            time.sleep(wait)
            sys.stdout.write("\033[F")  # Cursor up one line
        elif command == "cnt":
            count = int(value)
            if verbose >= 1: print '[%s] Changing number of packets to send to:%s' %(timeformat(timeleft()),str(count))
        elif command == "sec":
            apsecurity = value
            if verbose >= 1: print '[%s] Changing ap security to:%s' %(timeformat(timeleft()),apsecurity)
        elif command == "pay":
	    if value[:3] == 'b64':
		payload_plain = value[4:]
		payload = base64.b64encode(bytes(payload_plain))
                if verbose >= 1: print '[%s] Changing payload to %s base64(%s)' %(timeformat(timeleft()),payload,payload_plain)
	    else:
		payload = value[4:]
                if verbose >= 1: print '[%s] Changing plain payload to:%s' %(timeformat(timeleft()),payload)
        elif command == "gpo":
            gpioval = value.split('-')[0]
            gpiotime = value.split('-')[1]
            if verbose >= 1: print '[%s] Setting external GPIO to: %s - %s' %(timeformat(timeleft()),gpioval, gpiotime)
            gpioext.act(gpioval,gpiotime)
        elif command == "chn":
            channel = int(value)
            if verbose >= 2: print '[%s] Setting channel to:%s' %(timeformat(timeleft()),str(channel))
            sdot11.setchannel(channel)
        elif command == "src":
            src = value.upper()
            if verbose >= 1: print '[%s] Setting source MAC to: %s' %(timeformat(timeleft()),str(src).upper())
        elif command == "dst":
            dst = value.upper()
            if verbose >= 1: print '[%s] Settingg dst MAC to:%s' %(timeformat(timeleft()),dst)
        elif command == "bcn":
            ssid = value
            print '[%s] Sending %d beacons with SSID:%s (%s) CHAN:%d (%s MHz) BSSID:%s' %(timeformat(timeleft()), count, ssid, apsecurity, channel, frequency, str(src).upper())
            sdot11.beacon(src, count, ssid, apsecurity,payload)
        elif command == "prb":
            ssid = value
            print '[%s] Sending %d probe requests to SSID:%s CHAN:%d (%s MHz) from MAC:%s' %(timeformat(timeleft()), count, ssid, channel, frequency, dst.upper())
            sdot11.probereq(src, count, ssid, dst, payload)
        elif command == "prr":
            ssid = value
            print '[%s] Sending %d probe responses to MAC:%s  CHAN:%d (%s MHz) from BSSID:%s' %(timeformat(timeleft()), count, dst.upper(), channel, frequency, str(src).upper())
            sdot11.proberesp(src, count, ssid, dst, payload)
        elif command == "ass":
            ssid = value
            print '[%s] Sending %d association requests to BSSID:%s (%s) CHAN:%d (%s MHz) from MAC:%s' %(timeformat(timeleft()), count, dst.upper(), apsecurity, channel, frequency, str(src).upper())
            sdot11.assocreq(src, dst, count, ssid, apsecurity, payload)
        elif command == "aut":
            ssid = value
            print '[%s] Sending %d authentication requests to BSSID:%s (%s) CHAN:%d (%s MHz) from MAC:%s' %(timeformat(timeleft()), count, dst.upper(), apsecurity, channel, frequency, str(src).upper())
            sdot11.authreq(src, dst, count, ssid, apsecurity, payload)
        elif command == "dea":
            ssid = value
            print '[%s] Sending %d deauth requests to BSSID:%s (%s) CHAN:%d (%s MHz) from MAC:%s' %(timeformat(timeleft()), count, dst.upper(), apsecurity, channel, frequency, str(src).upper())
            sdot11.deauth(src, dst, count, ssid, payload)
        elif command == "ext":
            print "[%s] Requested to end execution at:%s" %(timeformat(timeleft()),datetime.now())
            exit()
        else:
            if verbose >= 2: print '[%s] Wrong command: %s(%s)' %(timeformat(timeleft()),command, value)
            return
    except KeyboardInterrupt:
	raise

def timeleft():
    elapsedtime = int(time.time())-ctfstart
    timeleft = ctftime - elapsedtime
    return timeleft

def timeformat(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return "%d:%02d:%02d" % (h, m, s)

# main routine
if __name__ == "__main__":
    # Check if OS is linux:
    oscheck()

    # Check for root privileges
    if os.geteuid() != 0:
        logging.debug("You need to be root to run this script!")
        exit()
    else:
        if verbose: logging.debug("You are running this script as root!")

    # Check if monitor device exists
    initmons(interfaces)

    # Start all gpio ports
    led = gpio(gpioled, 'out', 'blink')
    sled = gpio(gpiosend, 'out')
    #gpioin = gpio(gpiodisarm, 'in')

    # Begin blinking led
    if led.status: led.start()
    #blink(100, 0.5)

    # time checker for CTF bomb arm
    #gpioext = gpio(gpioarm, 'out')
    #if gpioext.status: gpioext.timecheck()

    # Start injection class
    sdot11 = Scapy80211(monifaces[0])
    sdot11.setchannel(channel)

    # Start timers
    print "Starting CTF execution at: %s" % datetime.now()
    ctfstart=int(time.time())
    print "Total CTF assigned time: %s" %timeformat(ctftime)

    # Start countdown screen
    if countdownscreen:
        os.system("python ./countdown.py %s" %str(ctftime))


    # parse file: ctf.conf
    fpattern=''
    try:
	ctfconf = open('ctf.conf', 'r')
        for line in ctfconf.readlines():
	    if not line.strip() or line[0:1] == "#":
		continue
	    else:
		fpattern = fpattern + line.replace("\n", ",").strip()
    except IOError:
	print 'Cannot open ctf.conf file, exiting!'
        exit()

    lpattern = fpattern.split(',')
    index1 = 0
    lpattern1 = []

    while index1 < len(lpattern):
        command = lpattern[index1][0:3]
        value = lpattern[index1][3:].translate(None, '()')
        if command == "rpt" or index1 == len(lpattern) - 1:
            if verbose >= 2: print 'repeating loop %s times...' % value
            indice = int(value)
            loop = True
            counter = 1
            while loop:
                index = 0
                while index < len(lpattern1):
                    command = lpattern1[index][0:3]
                    value = lpattern1[index][3:].translate(None, '()')
		    try:
	                executecommand(command, value)
		    except KeyboardInterrupt:
        	        print "CTRL+C pressed. Exiting!"
        		sys.exit(-1)
                    index += 1
                if counter == indice:
                    lpattern1 = []
                    loop = False
                if indice == 0: loop = True
                counter += 1
        else:
            lpattern1.append(command + '(' + value + ')')

        index1 += 1
