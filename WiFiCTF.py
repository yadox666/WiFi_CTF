#!/usr/bin/env python
# -*- coding: utf-8 -*-​
__version__ = '0.2'

try:
    import fcntl
    import sys, os, time
    import base64
    from nop import NOP
    from datetime import datetime
    from random import randint
    from platform import system
    from threading import Thread, Lock
    import logging, time, socket
    from subprocess import Popen, PIPE
    from signal import SIGINT,signal
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
except:
    print "Cannot import required package! Pip install it! %s"  %e.message
    exit()

# user defined variables
verbose = 1  ## verbosity level (0-3)
interface = 'wlan6' ## Wi-Fi interface/s ['wlan1','wlan2']
channel = 3  ## Channel to use by default
savecap=1  ## will save captured packets from attack

# Delete capfile before starting
capfile='./ctf_sentpkts.cap' ## directory and file name to save captured packets
try:
    os.remove(capfile)
except OSError:
    pass


# Hardware devices configuration
countdownhdmi=0 ## If 1 it will display a countdown full screen in HDMI connector
countdownlcd=0 ## If 1 it will display a countdown full screen
gpioctrl = 0 ## GPIO control on / off
camera_on=0

imagedir='./images'
gpiobase = '/sys/class/gpio'
gpioled = 6  ## GPIO port number for Status led
gpiosend = 5  ## GPIO port number when sending packets
gpioflash = 24  ## GPIO port number for white led as camera flash
gpioarm = 8  ## GPIO port number to force exploding the bomb
gpiodisarm = 7  ## GPIO port number to disarm the bomb by button
gpioexplode = 9  ## GPIO port to connect explode mechanism for cartridge
gpioexplode2 = 10  ## GPIO port to connect explode mechanism for second cartridge
gpioext = 11  ## GPIO port number to external peripheral
gpiobuzzer = 18  ## GPIO port number for a buzzer

# Default system variables
ctftime=3600  ## Default CTF duration in seconds
disarmpayload='DisarmITn0w!!!'  ## Disarm the bomb sending various Probe Request packets with this SSID
activatepayload='HelloBomb!'  ## Disarm the bomb sending various Probe Request packets with this SSID
apsecurity = 'OPEN'  ## open, wep, wpa, wpa2
ssid = 'CTF!!!'  ## default SSID to use
count = 100  ## Default number of packets to send
src = RandMAC()  ## source ip from packets
dst = 'ff:ff:ff:ff:ff:ff'  ## Destination address for beacons and probes
broadcast = 'ff:ff:ff:ff:ff:ff'  ## Destination address for beacons and probes
sc = randint(1, 4096)
payload = ''
frequency = ''
lock = Lock()
DN = open(os.devnull, 'w')
gpioarmnc = 1  ## Arm mechanism is normally open (0) or normally closed (1)
gpiodisarmnc = 1  ## Disarm mechanism Normally open (0) or normally closed (1)
payload_ie = 221  ## 802.11 Element ID to include payload
payload_preffix = 'CTF'  ## When using element ID 221 the first 3 bytes are for the manuf OUI
closing = 0
activate = 0
wfp = 0
intfmon=''
winner=''
ctfstart=int(time.time())
lcd = None

# Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']

def stoptimers(reason=0):
    global lcd
    if countdownhdmi:
        logging.debug("Stopping HDMI countdown timer!")
        hdmi.terminate()
        time.sleep(0.2)
	hdmi = None
    if countdownlcd:
        logging.debug("Stopping LCD countdown timer!")
        lcd.terminate()
        time.sleep(0.3)
	lcd = None
	if reason == 1:
            lcd = subprocess.Popen(['./lcdprint', 'run !!!!', '4'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	elif reason == 2:
            lcd = subprocess.Popen(['./lcdprint', 'dISARmEd', '4'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	elif reason == 3:
            lcd = subprocess.Popen(['./lcdprint', winner[-8], '4'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def PacketHandler(pkt):
    global winner, activate, activatepayload, wfp
    sta = pkt.addr2.upper()
    ssid = pkt.info
    if ssid == disarmpayload:
        if self.savecap:
            try:
		wrpcap(capfile, pkt, append=True)
            except:
                self.savecap=0
        ret = sled.is_lit
        sled.blink(on_time=1,off_time=0.4,n=1)
	logging.debug("Received Probe Request packet from station %s with payload: %s. Disarming bomb!" %(sta,ssid))
	winner=sta.translate(None, ':')
	timer.disarm_bomb()
        if ret: sled.on()
    elif ssid == activatepayload and not activate and wfp:
	logging.debug("Received Probe Request packet from station %s with payload: %s. Activating bomb!" %(sta,ssid))
	activate = 1
        if self.savecap:
            try:
		wrpcap(capfile, pkt, append=True)
            except:
                self.savecap=0


class Sniffer(Thread):  # Scapy sniffer thread
    def __init__(self):
        Thread.__init__(self)
        Thread.daemon = True

    def run(self):
        try:
            if verbose: logging.debug("Start sniffing data with interface %s" % intfmon)
            sniff(iface=intfmon, prn=PacketHandler, lfilter=lambda p:(Dot11ProbeReq in p), store=0)
        except Exception as e:
            logging.error("Cannot start sniffer thread with interface %s! %s" %(intfmon,e.message))


class CheckTimer(Thread):
    def __init__(self):
	global gpioctrl
        Thread.__init__(self)
        Thread.daemon = True
	if gpioctrl:
	        self.statusled = LED(gpioled)
	        self.arm = Button(gpioarm)
	        self.disarm = Button(gpiodisarm)
		self.buzzer= Buzzer(gpiobuzzer)
	else:
	        self.statusled = NOP()
	        self.arm = NOP()
	        self.disarm = NOP()
		self.buzzer= NOP()
	

    def run(self):
        if gpioarmnc:
            self.arm.when_released = self.arm_bomb
        else:
	    self.arm.when_pressed = self.arm_bomb

        if gpiodisarmnc:
            self.disarm.when_released = self.disarm_bomb
        else:
	    self.disarm.when_pressed = self.disarm_bomb

	self.timercheck()

    def timercheck(self):
	ledexec=1
	ledinterval=15  ## percentage of ctf accelerate led light freq
	ledfreq=1  ## time to flash led on
	i=0
        while not closing:
	    elapsedtime = int(time.time())-ctfstart
	    percent=float(elapsedtime)/ctftime*100
            if timeleft() < 1:
                logging.debug("CTF finished! Time left: %s" %timeformat(timeleft()))
		self.arm_bomb()
		closeall(0,0)

	    if percent >= ledinterval*i:
		if ledexec:
		    ledfreq = 1-(float(percent)/100)+0.1
		    self.statusled.off()
		    time.sleep(0.4)
	            self.statusled.blink(ledfreq,ledfreq-0.1)
		    if i == 100/ledinterval:  ## Last round
			self.buzzer.source = self.statusled.values
		i += 1
		ledexec=1
            time.sleep(0.4)

    def disarm_bomb(self):
	self.statusled.on()
	self.buzzer.on()
	stoptimers(2)
	takephoto()
	time.sleep(3)
	self.statusled.off()
	self.buzzer.off()
	takephoto()
	logging.debug("Disarm button pressed! Disarming bomb now!")
	self.statusled.off()
	stoptimers(3)
	closeall(0,0)

    def arm_bomb(self):
	if gpioctrl:
	    explode = OutputDevice(gpioexplode, active_high=False)
	    explode2 = OutputDevice(gpioexplode2, active_high=False)
	    takephoto()
	    logging.debug("ARM button pressed! Arming bomb now!")
	    self.statusled.blink(on_time=0.05, off_time=0.05)
	    self.buzzer.source = self.statusled.values
	else:
	    logging.debug("Arming bomb now!")

	stoptimers(1)
	if gpioctrl:
	    time.sleep(2.5)
	    explode.on()
	    time.sleep(0.8)
	    explode2.on()
	    takephoto()
	    time.sleep(2)
	    takephoto()
            explode.off()
	    time.sleep(1)
            explode2.off()
	    takephoto()
	closeall(0,0)

def closeall(signal,frame):
    global closing
    closing = 1
    logging.debug('Ending execution!')
    sled.off()
    exit()


def takephoto():
    if camera_on:
	flash.on()
	date = datetime.now().isoformat()
	camera.capture('%s/%s.jpg' %(imagedir,date))
	time.sleep(0.2)
	flash.off()


def oscheck():
    osversion = system()
    if verbose:
        logging.debug("Operating System: %s" % osversion)
    if osversion != 'Linux':
        logging.debug("This script only works on Linux OS! Exitting!")
        exit(1)


def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac


def initmon(intfparent):
    global intfmon, ignore
    logging.debug("Wi-Fi nterface to use: %s" %intfparent)
    if not os.path.isdir("/sys/class/net/" + interface):
        logging.debug("WiFi parent interface %s does not exist! Cannot continue!" % interface)
        exit(1)
    else:
        intfmon = 'mon' + intfparent[-1]
        if os.path.isdir("/sys/class/net/" + intfmon):
            logging.debug("WiFi interface %s exists! Deleting it!" % (intfmon))
            try:
                # create monitor interface using iw
                os.system("iw dev %s del" % intfmon)
                time.sleep(0.5)
            except OSError as oserr:
                logging.debug("Could not delete monitor interface %s. %s" % (intfmon, oserr.message))
                os.kill(os.getpid(), SIGINT)
                sys.exit(1)
        try:
            # create monitor interface using iw
	    os.system('rfkill unblock wlan')
            time.sleep(0.3)
            os.system("ifconfig %s down" % interface)
            time.sleep(0.3)
            os.system("iwconfig %s mode monitor" % interface)
            time.sleep(0.3)
            os.system("iw dev %s interface add %s type monitor" % (interface, intfmon))
            time.sleep(0.3)
            os.system("ifconfig %s up" % intfmon)
            if verbose:
                logging.debug("Creating monitor VAP %s for parent %s..." % (intfmon, interface))
        except OSError as oserr:
            logging.debug("Could not create monitor %s. %s" % (intfmon, oserr.message))
            os.kill(os.getpid(), SIGINT)
            sys.exit(1)
        # Get actual MAC addresses
        macaddr1 = GetMAC(intfmon).upper()
        ignore.append(macaddr1)
        if verbose: logging.debug("Actual %s MAC Address: %s" % (interface, macaddr1))
        macaddr = GetMAC(intfmon).upper()
        if macaddr1 != macaddr:
            ignore.append(macaddr);
            if verbose:
                logging.debug("Actual %s MAC Address: %s" % (intfmon, macaddr))


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
    def __init__(self, intfparent='wlan1', intfmon='mon1'):
        self.intfparent = intfparent
        self.intfmon = intfmon
        conf.iface = self.intfmon
	self.savecap = savecap

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
	eltpayload = Dot11Elt(ID=payload_ie,info=payload_preffix+payload) ## vendor WPS
        pkt = RadioTap() / Dot11(type=0, subtype=8, addr1=broadcast.upper(), addr2=src, addr3=src, SC=next_sc()) / beacon / essid / rsn / Dot11EltRates() / eltpayload / dsset / tim
        if verbose >= 3: pkt.show()
        if verbose >= 2: print '[*] 802.11 Beacon: SSID=[%s], count=%d' % (ssid, count)
        try:
            sled.on()
            sendp(pkt, iface=self.intfmon, count=count, inter=0.100, verbose=0)
            if self.savecap:
                try:
		    wrpcap(capfile, pkt, append=True)
                except:
                    self.savecap=0
            sled.off()
        except Exception as e:
	    logging.error('Cannot send packets. %s' %e.message)
            

    def probereq(self, src, count, ssid, dst, payload):
        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        dsset = Dot11Elt(ID='DSset', info=chr(channel))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendorWPS
        pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=dst, addr2=src, addr3=dst, SC=next_sc()) / param / essid / Dot11EltRates() / eltpayload / dsset
        if verbose >= 3: pkt.show()
        if verbose >= 2: print '[*] 802.11 Probe Request: SSID=[%s], count=%d' % (ssid, count)
        try:
            sled.on()
            sendp(pkt, count=count, inter=0.1, verbose=0)
            if self.savecap:
                try:
		    wrpcap(capfile, pkt, append=True)
                except:
                    self.savecap=0
            sled.off()
        except Exception as e:
	    logging.error('Cannot send packets. %s' %e.message)

    def proberesp(self, src, count, ssid, dst, payload):
        param = Dot11ProbeResp(beacon_interval=0x0064, cap=0x2104)
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        dsset = Dot11Elt(ID='DSset', info=chr(channel))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendorWPS
        pkt = RadioTap() / Dot11(subtype=5, addr1=src, addr2=dst, addr3=dst, SC=next_sc()) / param / essid / Dot11EltRates() / eltpayload / dsset
        # If we are an RSN network, add RSN data to response
        if security[0:3] == 'WPA':
            probe_response_packet[Dot11ProbeResp].cap = 0x3101
            rsn_info = Dot11Elt(ID='RSNinfo', info=RSN)
            probe_response_packet = probe_response_packet / rsn_info
        try:
            sled.on()
            sendp(pkt, count=count, inter=0.1, verbose=0)
            if self.savecap:
                try:
		    wrpcap(capfile, pkt, append=True)
                except:
                    self.savecap=0
            sled.off()
        except Exception as e:
	    logging.error('Cannot send packets. %s' %e.message)

    def authreq(self, src, dst, count, ssid, apsecurity, payload):
        # authentication with open system
        param = Dot11Auth(algo=0, seqnum=1, status=0)
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendorWPS
        pkt = RadioTap() / Dot11(subtype=0xb, addr1=dst, addr2=src, addr3=dst, SC=next_sc()) / param / essid / eltpayload
        sled.on()
        res = srp(pkt, iface=self.intfmon, count=count, timeout=2)
        if self.savecap:
            try:
	        wrpcap(capfile, pkt, append=True)
            except:
                self.savecap=0
        sled.off()
        if res:
            res.summary()
            logging.debug("Got answer from " + res.addr2)
        else:
            logging.debug("Got no answer from " + dst)

    def assocreq(self, src, dst, count, ssid, apsecurity, payload):
        # association request
        param = Dot11AssoReq()
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendorWPS
        pkt = RadioTap() / Dot11(type=0, subtype=0, addr1=dst, addr2=src, addr3=dst,
                                 SC=next_sc()) / param / essid / Dot11EltRates() / eltpayload
        sled.on()
        res = srp(pkt, iface=self.intfmon, count=count, timeout=2)
        if self.savecap:
            try:
	        wrpcap(capfile, pkt, append=True)
            except:
                self.savecap=0
        sled.off()
        if res:
            logging.debug("Got answer from " + res.addr2)
        else:
            logging.debug("Got no answer from " + ssid)

    def deauth(self, src, dst, count, ssid, payload):
        # Deauthentication request
	eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload_preffix+payload) ## vendorWPS
        param = Dot11Deauth() / eltpayload
        pkt = RadioTap() / Dot11(addr1=src, addr2=dst, addr3=dst, SC=next_sc()) / param  ## AP to STA deauth
        pkt2 = RadioTap() / Dot11(addr1=dst, addr2=src, addr3=dst, SC=next_sc()) / param  ## STA to AP deauth
        res = srp1(pkt, retry=5, iface=self.intfmon, timeout=2)
        if res:
            logging.debug("Got answer from " + res.addr2)
        else:
            logging.debug("Got no answer from Station: " + str(src))
        sled.on()
        res = srp(pkt2, count=count, iface=self.intfmon, timeout=2)
        if self.savecap:
            try:
	        wrpcap(capfile, pkt, append=True)
            except:
                self.savecap=0
        sled.off()
        if res:
            logging.debug("Got answer from " + res.addr2)
        else:
            logging.debug("Got no answer from AP: " + dst)

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
            if verbose >= 2: logging.debug("Setting %s to channel: %s (%s MHz)" % (self.intfmon, channel, frequency))
        except OSError as e:
            logging.debug('Could not execute iw!')
            os.kill(os.getpid(), SIGINT)
            return False
        for line in proc.communicate()[1].split('\n'):
            if len(line) > 2:  # iw dev shouldnt display output unless there's an error
		print line
                logging.debug("Error setting channel %s for %s" % (channel, self.intfmon))
                return False


def executecommand(command, value):
    global ctftime, ctfstart, count, src, dst, ssid, channel, apsecurity, payload, closing, disarmpayload, activate, wfp, activatepayload, lcd
    try:
	if closing:
	    return
        if command == "slp":
            logging.debug('[%s] Sleeping %s seconds...' %(timeformat(timeleft()),value))
	    for i in range(int(value)):time.sleep(1)
            sys.stdout.write("\033[F")  # Cursor up one line
        if command == "wai":
            wait=ctfstart+(int(value)*60)-int(time.time())
	    if wait < 0:
		wait=1
            logging.debug('[%s] Sleeping %d seconds until %s minutes from CTF Start...' %(timeformat(timeleft()),wait,value))
	    for i in range(wait): time.sleep(1)
            sys.stdout.write("\033[F")  # Cursor up one line
        elif command == "ctf":
            ctftime = int(value)
            if verbose >= 1: logging.debug("Fixing CTF duration to: %s" %(timeformat(ctftime)))
    	    # Start timers
    	    logging.debug("Starting CTF execution at: %s" % datetime.now())
            ctfstart=int(time.time())
    	    # Start countdown screen and LCD
    	    if countdownhdmi:
                logging.debug("Starting HDMI countdown timer: %s" %timeformat(timeleft()))
		if hdmi: 
		    subprocess.Pkill(hdmi.pid)
		    time.sleep(1)
                hdmi = subprocess.Popen(['python', './countdown.py', str(ctftime)], shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if countdownlcd:
                logging.debug("Starting LCD countdown timer: %s" %timeformat(timeleft()))
		if lcd:
		    subprocess.Pkill(hdmi.pid)
		    time.sleep(1)
                lcd = subprocess.Popen(['./countdown', str(ctftime)], shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        elif command == "cnt":
            count = int(value)
            if verbose >= 1: logging.debug('[%s] Setting number of packets to send to:%s' %(timeformat(timeleft()),str(count)))
        elif command == "sec":
            apsecurity = value
            if verbose >= 1: logging.debug('[%s] Setting ap security to:%s' %(timeformat(timeleft()),apsecurity))
        elif command == "snf":
            disarmpayload = value
            if verbose >= 1: logging.debug('[%s] Setting ProbeReq disarm payload to:%s' %(timeformat(timeleft()),disarmpayload))
        elif command == "wfp":
            activatepayload = value
	    wfp = 1
            if verbose >= 1: logging.debug('[%s] Waiting for activation payload:%s' %(timeformat(timeleft()),activatepayload))
	    while not activate and not closing:
                time.sleep(3)
        elif command == "pay":
	    if value[:3] == 'b64':
		payload_plain = value[4:]
		payload = base64.b64encode(bytes(payload_plain))
                if verbose >= 1: logging.debug('[%s] Setting payload to %s base64(%s)' %(timeformat(timeleft()),payload,payload_plain))
	    else:
		payload = value[4:]
                if verbose >= 1: logging.debug('[%s] Setting plain payload to:%s' %(timeformat(timeleft()),payload))
        elif command == "gpo":
            gpioval = value.split('-')[0]
            gpiotime = value.split('-')[1]
            if verbose >= 1: logging.debug('[%s] Setting external GPIO to: %s - %s' % (timeformat(timeleft()),gpioval, gpiotime))
            gpioext.on()
	    for i in range(3): time.sleep(1)
	    gpioext.off()
        elif command == "chn":
            channel = int(value)
            if verbose >= 1: logging.debug('[%s] Setting %s to channel: %s (%s MHz)' % (timeformat(timeleft()),intfmon, str(channel), frequency))
            sdot11.setchannel(channel)
        elif command == "src":
            src = value.upper()
            if verbose >= 1: logging.debug('[%s] Setting source MAC to: %s' %(timeformat(timeleft()),str(src).upper()))
        elif command == "dst":
            dst = value.upper()
            if verbose >= 1: logging.debug('[%s] Settingg dst MAC to:%s' %(timeformat(timeleft()),dst))
        elif command == "bcn":
            ssid = value
            logging.debug('[%s] Sending %d beacons with SSID:%s (%s) CHAN:%d (%s MHz) from BSSID:%s' %(timeformat(timeleft()), count, ssid, apsecurity, channel, frequency, str(src).upper()))
            sdot11.beacon(src, count, ssid, apsecurity,payload)
        elif command == "prb":
            ssid = value
            logging.debug('[%s] Sending %d probe requests to SSID:%s CHAN:%d (%s MHz) to MAC:%s' %(timeformat(timeleft()), count, ssid, channel, frequency, dst.upper()))
            sdot11.probereq(src, count, ssid, dst, payload)
        elif command == "prr":
            ssid = value
            logging.debug('[%s] Sending %d probe responses to MAC:%s  CHAN:%d (%s MHz) to BSSID:%s' %(timeformat(timeleft()), count, dst.upper(), channel, frequency, str(src).upper()))
            sdot11.proberesp(src, count, ssid, dst, payload)
        elif command == "ass":
            ssid = value
            logging.debug('[%s] Sending %d association requests to BSSID:%s (%s) CHAN:%d (%s MHz) from MAC:%s' %(timeformat(timeleft()), count, dst.upper(), apsecurity, channel, frequency, str(src).upper()))
            sdot11.assocreq(src, dst, count, ssid, apsecurity, payload)
        elif command == "aut":
            ssid = value
            logging.debug('[%s] Sending %d authentication requests to BSSID:%s (%s) CHAN:%d (%s MHz) from MAC:%s' %(timeformat(timeleft()), count, dst.upper(), apsecurity, channel, frequency, str(src).upper()))
            sdot11.authreq(src, dst, count, ssid, apsecurity, payload)
        elif command == "dea":
            ssid = value
            logging.debug('[%s] Sending %d deauth requests to BSSID:%s (%s) CHAN:%d (%s MHz) from MAC:%s' %(timeformat(timeleft()), count, dst.upper(), apsecurity, channel, frequency, str(src).upper()))
            sdot11.deauth(src, dst, count, ssid, payload)
        elif command == "ext":
            logging.debug("[%s] Requested to end execution at:%s" %(timeformat(timeleft()),datetime.now()))
            closeall(0,0)
        else:
            if verbose >= 2: logging.error('[%s] Wrong command: %s(%s)' %(timeformat(timeleft()),command, value))
            return
    except Exception as e:
        logging.error('Cannot parse command. %s' %e.message)

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

    # Print init banner
    print "\n=========================================================="
    print "      ▌ ▌▗   ▛▀▘▗     ▞▀▖       ▐      ▛▀▘ "
    print "      ▌▖▌▄   ▙▄ ▄     ▌         ▜▀     ▙▄  "
    print "      ▙▚▌▐ ▄ ▌  ▐     ▌ ▖apture ▐ ▖he  ▌ lag"
    print "      ▘ ▘▀   ▘  ▀     ▝▀         ▀     ▘    "
    print "      Wi-Fi (802.11) CTF GENERATOR SCRIPTING LANGUAGE"
    print "==========================================================\n"

    # Check if OS is linux:
    oscheck()

    # Check for root privileges
    if os.geteuid() != 0:
        logging.debug("You need to be root to run this script!")
        exit()
    else:
        if verbose: logging.debug("You are running this script as root!")

    # Check if monitor device exists
    initmon(interface)

    # Interrupt handler to exit
    signal(SIGINT, closeall)

    # Start injection class
    sdot11 = Scapy80211(interface,intfmon)
    sdot11.setchannel(channel)

    # Start sniffer
    Sniffer().start()

    # Start camera
    if camera_on:
	try:
	    from picamera import PiCamera
            camera = PiCamera()
	except Exception as e:
	    logging.error("Pi Camera error! %s" %e.message)
	    camera_on=0
	if not os.path.exists(imagedir):
            try:
                os.makedirs(imagedir)
            except OSError as e:
                logging.error("Cannot create directory: images")
                imagedir = "./"

    # Start GPIOs
    if gpioctrl:
	try:
	    from gpiozero import LED,Button,Buzzer,OutputDevice
	except Exception as e:
	    logging.error("Cannot import gpiozero package! %s"  %e.message)
	    gpioctrl=0
	sled = LED(gpiosend)
	flash = LED(gpioflash)
	gpioext = LED(gpioext)
	timer = CheckTimer()
	timer.start()

    if not gpioctrl:
	sled = NOP()
	flash = NOP()
	gpioext = NOP()
	timer = CheckTimer()
	timer.start()

    # parse file: ctf.conf to oneline separated by commas
    fpattern=''
    try:
	ctfconf = open('ctf.conf', 'r')
        for line in ctfconf.readlines():
	    if not line.strip() or line[0:1] == "#":
		continue
	    else:
		fpattern = fpattern + line.replace("\n", "~,~").strip()
    except IOError:
	logging.error('Cannot open ctf.conf file, exiting!')
        exit()

    # Create lpattern array   
    lpattern = fpattern.split('~,~')

    # Last command has to be rpt
    if lpattern[-1][:3] != 'rpt':
	lpattern.append('rpt(0)')

    # Parse and remove ctf time to avoid repetitions
    index = 0
    for item in lpattern[:]:
        command = item[:3]
        value = item[3:].translate(None, '()')
	if command == "ctf":
            executecommand(command, value)
	    lpattern.remove(item)
    
    index1 = 0
    firstpass=1
    lpattern1 = []  

    try:
	## Cycle through lpattern array
        while index1 < len(lpattern) and not closing:
            command = lpattern[index1][0:3]
            value = lpattern[index1][3:].translate(None, '()')

	    ## Read commands until the end or until next repeat rpt
            if command == "rpt" or index1 == len(lpattern) - 1:

		## At the end show message
                if firstpass:
		    firstpass=0
	        else:
		    if verbose >= 1: logging.debug('Repeating loop %s times...' % value)

                indice = int(value)+1
                loop = True
                counter = 1

		## Execute commands and repeat loops if necessary
                while loop and not closing:
                    index = 0
                    while index < len(lpattern1):
                        command = lpattern1[index][0:3]
                        value = lpattern1[index][3:].translate(None, '()')
                        executecommand(command, value)
                        index += 1
                    if counter == indice:
                        lpattern1 = []
                        loop = False
                    if indice == 0: loop = True
                    counter += 1
            else:
		## Append commands to provisional list to repeat (rpt) if necessary
                if command != "rpt": 
		    lpattern1.append(command + '(' + value + ')') 
            index1 += 1

	print
	tl = timeleft()
        while timeleft() > -5 and not closing:
            time.sleep(5)
	    tl=timeleft()
	    if tl > 5:
		sys.stdout.write('\r'+"Time left: %s" %timeformat(tl))
	    else:
		sys.stdout.write('\r                                \n')
	    sys.stdout.flush()

    except KeyboardInterrupt:
	closeall(0,0)
