Wi-Fi CTF Generator
-------------------
Author:  Yago F. Hansen (2017)

Description:
------------
This project was created to help creating Wi-Fi (802.11) related CTFs for
security CONs. This python script uses scapy library to create or forge
different type of 802.11 packets with different fields on them. It allows
the usage of GPIO for connecting leds, lights or peripherals.

    * A small embedded device connected by GPIO to a fake bomb consistent in a confetti shooter (no danger about fire!).
      The CTF starts in a fixed time showing a countdown in a monitor with the fixed time. The embedded system will begin
      to send periodically some clues about the robust Wi-Fi key needed for login to the existent Wi-Fi network. This clues will
      be embedded in 802.11 packets that should be sniffed by the participants. The clues are more complex from the beginning,
      to get easier as the time runs. There's only one winner, but the clues will be introduced in the CTF platform as flags getting more
      points on every discoverd flag. As you can build the Wi-Fi password, the participant can connect to the AP present in the
      embedded device. There's a hotspot that will show you the bomb GUI in which he has to respond some questions to
      deactivate the bomb. If no one wins it will explode. If somebody deactivates it, he will get the last flag.


CTF name:
---------
    * "Disarm the bomb!"


CTF  knowledge requirements:
----------------------------
    * 802.11 packet dissection knowledge
    * Monitor mode packet sniffing


Required materials for the participants:
----------------------------------------
    * Wireshark
    * Linux (Kali Linux preferred)
    * Monitor mode wireless card (Alfa or TP-LINK TL-WN722N)
    * Python and scapy (optional)


Bomb necessary hardware:
------------------------
    * Raspberry PI 3 model B+ card
    * MicroSD card
    * USB Power adapter 2A/5V DC or Power bank > 7500 mAh
    * Rapio ProHat or similar GPIO connection breadboard
    * HDMI Monitor for countdown (optional)
    * HDMI male /HDMI male cable (optional)
    * LCD 7x8 display based on TM1638 chipset (optional)
    * 3x LEDS (red, white, yellow) 
    * 3.3V DC active buzzer
    * color patch breadboard cables (male/male, male/female)
    * Raspberry PI camera (optional)
    * Wi-Fi monitor mode card (TP-LINK WL-722N recommended)
    * 2 Channel 5V High Level Trigger Relay Module GPIO controlled 
    * 11.1 V DC LiPo / LiIon small battery to activate 12 confetti canon after relay 
    * Confetti electric canon (or another bomb design). Free of fire.



Clues and flags:
----------------
    * Every new clue or flag: A BIG LIGHT WILL FLASH SOME SECONDS BEFORE SENDING IT.
    * All sent packets are probe requests / probe responses and beacons! Beacon sends some clues!
    * Clue 1: TIME LEFT: 4:51:23 - SSID: BOMB_HERE!!! - LEN(Passwd)=12
    * Clue 2: (3 times): ord(Passwd[1])=67
    * Last clue:  11 characters in total. Last has to be broken by brute force the login.


Usage:
------
Create a file with name ctf.conf in the same directory as the python script,
including a command on each line. If the line is empty or begins with "#" 
character it will be ignored. The following commands are accepted:

Injection pattern to define by user (secuential run):
                     ctf(n): CTF duration in seconds - Should be first parameter
                     bcn(ssid): send beacons with ssid
                     prb(ssid): send probe requests with ssid 
                     prr(ssid): send probe response from ssid 
                     aut(ssid): send authentication request to dst
                     ass(ssid): send association request to dst
                     dea(ssid): send deauthentication to dst 
                     pay(b64:payload): include payload in packets (optionally encode base64)
                     sec(wpa): change security to WPA (OPN,WEP,WPA,WPA2,EAP), 
                     cnt(n): next command will send n packets, 
                     chn(n): set channel to n 
                     src(mac): new_source (mac), 
                     dst(mac): new_destination (mac), 
                     gpo(n-1): set extra gpio n to 1 or 0
                     snf(payload): Sniff for a probe request with payload to disarm bomb
                     slp(n): sleep n seconds,
                     wai(min): continue when elapsed n minutes from ctf start
                     rpt(n): repeat n times previous commands
                     ext(): exit application

Configure the time of the CTF game, using the following var in the python script (in seconds):
	ctftime=n

Create the ctf.conf file for the CTF, in order to send the clues during the duration of the game.
Please control that the timming of the ctf.conf can be done inside of the ctftime defined time.

All the logs of the CTF will be saved to syslog daemon. If you suspect, that something is wrong
please revise the syslog file of the raspberry pi.



ctf.conf Example:
-----------------

	ctf(3600)
	snf(DisarmITn0w!!!)
	cnt(100)
	sec(OPEN)
	bcn(yadox)
	slp(4)
	prb(yadox)
	slp(1)
	cnt(50)
	bcn(test)
	cnt(10)
	prb(test)
	rpt(0)


Configuration of GPIO ports used in examples:
-----------------------------------------------
(BCM Port number / Not Raspberry printed ports)

gpioled = 6  ## GPIO port number for Status LED
gpiosend = 5  ## GPIO port number for LED when sending packets
gpioflash = 24  ## GPIO port number for white LED as camera flash

gpioarm = 8  ## GPIO port number to force exploding the bomb
gpiodisarm = 7  ## GPIO port number to disarm the bomb by button
gpioexplode = 9  ## GPIO port to connect explode mechanism for cartridge
gpioexplode2 = 10  ## GPIO port to connect explode mechanism for second cartridge
gpioext = 11  ## GPIO port number to external peripheral
gpiobuzzer = 18  ## GPIO port number for a 3.3V active BUZZER


RASPBERRY PI CAMERA
-------------------
If you connect a Raspberry PI camera, you can use it to take a picture when
disarming the bomb (usefull if you cut the cable to try to disarm it)
Just connect the camera, and if recognized, it will enable it automatically.


COUNTDOWN SEQUENCE IN HDMI CONNECTOR
------------------------------------
If you want to display the countdown in a monitor, activate the variable:
	countdownhdmi=1
But you have to run the script in a terminal window on Raspberry GUI. Not in
terminal console without GUI.


COUNTDOWN SEQUENCE IN LCD DISPLAY
---------------------------------
If you want to use an LCD display (based in chipset TM-1638) available in ebay
or Amazon, just connect it to pins:
	DIO = 17
	CLK = 27
	STB = 22
To activate it, use the variable:
	countdownlcd=1


WAYS TO DISARM/DEACTIVATE THE BOMB
----------------------------------
1. Cut the right cable. There are two cables connected (gpioarm,gpiodisarm) that have to be connected.
   You can offer clues to determine wich colour have to be cutted. If camera is connected, there will
   be a picture showing the player cuting the cable in images directory.
2. Send Probe Request packets in right channel asking for an ESSID (payload) to be defined in variable
   or ctf.conf command snf(payload).


FLAGS FOR THE CTF PLATFORM
--------------------------
Include the different flags in form of payload of different packets to be sent in selected channels,
using commands in ctf.conf file. You can also send clues to help the players to determine which is
the disarm cable colour to cut.

How to achieve the main flag:
    * The participant has to discover WPA2/PSK key (12 characters) and connect to it.
    * The participant has to login and enter the hotspot portal to disarm the bomb responding some questions.

Number of flags:
    * Defined by the ctf.conf complexity

Complexity:
    * Defined by the ctf.conf complexity

Duration:
    * Defined inside the python script with the ctfduration variable.
