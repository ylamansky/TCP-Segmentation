#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author: N0dr4x (n0dr4x@protonmail.com)


from scapy.all import *
from scapy.all import TCP, IP, sr1, fragment
from threading import Thread
import time

##DONT FORGET TO LISTENNNNNNNNNNNN


class TcpSession:

   def __init__(self,target):
      self.seq = 0
      self.ack = 0
      self.ip = IP(dst=target[0])
      self.sport = 1337 #or 80; can specify. original documentation says 1337 for wireshark
      self.dport = target[1]
      self.connected = False
      self._ackThread = None
      self._timeout = 3
      
   def _ack(self, p):
      self.ack = p[TCP].seq + len(p[Raw])
      ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
      send(ack)

   def _ack_rclose(self):
      self.connected = False

      self.ack += 1
      fin_ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
      ack = sr1(fin_ack, timeout=self._timeout)
      self.seq += 1

      assert ack.haslayer(TCP), 'TCP layer missing'
      assert ack[TCP].flags & 0x10 == 0x10 , 'No ACK flag'
      assert ack[TCP].ack == self.seq , 'Acknowledgment number error'
      

   def _sniff(self):
      s = L3RawSocket()
      while self.connected:
         p = s.recv(MTU)
         if p.haslayer(TCP) and p.haslayer(Raw) \
            and p[TCP].dport == self.sport :
               self._ack(p)
         if p.haslayer(TCP) and p[TCP].dport == self.sport \
            and p[TCP].flags & 0x01 == 0x01 : # FIN
               self._ack_rclose()
            
      s.close()
      self._ackThread = None
      print('Acknowledgment thread stopped')

   def _start_ackThread(self):
      self._ackThread = Thread(name='AckThread',target=self._sniff)
      self._ackThread.start()

   def connect(self):
      self.seq = random.randrange(0,(2**32)-1)

      syn = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
      syn_ack = sr1(syn, timeout=self._timeout)
      self.seq += 1
      if syn_ack == None:
         print("SYN_ACK AINT SHIT ERROR RIGHT HEEERRRRR")
      else:
         print("oh we biiiiiiig chillin")
      assert syn_ack.haslayer(TCP) , 'TCP layer missing'
      assert syn_ack[TCP].flags & 0x12 == 0x12 , 'No SYN/ACK flags'
      assert syn_ack[TCP].ack == self.seq , 'Acknowledgment number error'

      self.ack = syn_ack[TCP].seq + 1
      ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack) # / "musubi"
      send(ack)

      self.connected = True
      self._start_ackThread()
      print('Connected')

   def close(self):
      self.connected = False

      fin = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
      fin_ack = sr1(fin, timeout=self._timeout)
      self.seq += 1

      assert fin_ack.haslayer(TCP), 'TCP layer missing'
      assert fin_ack[TCP].flags & 0x11 == 0x11 , 'No FIN/ACK flags'
      assert fin_ack[TCP].ack == self.seq , 'Acknowledgment number error'

      self.ack = fin_ack[TCP].seq + 1
      ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq,  ack=self.ack)
      send(ack)

      print('Disconnected')

   def build(self, payload):
      psh = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payload
      self.seq += len(psh[Raw])
      return psh

   def send(self, payload):
      psh = self.build(payload)
      ack = sr1(psh, timeout=self._timeout)

      assert ack.haslayer(TCP), 'TCP layer missing'
      assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'
      assert ack[TCP].ack == self.seq , 'Acknowledgment number error'


# Create the session object and connect to host 192.168.13.37 port 80
sess = TcpSession(('192.168.56.105',80))
sess.connect()


#for normal packet with full payload "musubi"
# Build next packet and send it fragmented (layer 2)
p = sess.build("abcdefghijkl")
send(fragment(p, fragsize=1500))

# Send 10 ACK packets with different sequence numbers
for i in range(10):
    ack_packet = sess.ip / TCP(sport=sess.sport, dport=sess.dport, seq=sess.seq + i, flags='A', ack=sess.ack)
    send(ack_packet)
    time.sleep(0.1)  # Small delay between packets to avoid overwhelming the system

time.sleep(5)
sess.close()



#Direct send data through the session and close
#sess.send("musubi")
#sess.close()

# #Session object can be reusable
# sess.connect()
# sess.send('GET /robot.txt HTTP/1.1\r\n\r\n')
# sess.close()