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
         print("There is no SYN-ACK")
      else:
         print("YAY Syn-Ack!")
      assert syn_ack.haslayer(TCP) , 'TCP layer missing'
      assert syn_ack[TCP].flags & 0x12 == 0x12 , 'No SYN/ACK flags'
      assert syn_ack[TCP].ack == self.seq , 'Acknowledgment number error'

      self.ack = syn_ack[TCP].seq + 1
      ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
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

   def build(self, payloads):
      #THIS WORKS FOR SEGMENTING THE PACKET IN HALF!! FOR CASE G; abcdef and ghijkl
      #just testing index from list
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payloads[:6]
      # self.seq += len(payloads[:6])
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payloads[6:]
      # self.seq += len(payloads[6:])
      # #self.seq += len(psh1[Raw]) + len(psh2[Raw])
      # #self.seq += len(payloads[:6])
      # return psh1, psh2

      # # CASE G
      # #USE THIS
      # #dealing with sequence numbers themselves
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/ "abcdef"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq + 6, ack=self.ack)/ "ghijkl"
      # #self.seq += len(psh1[Raw]) + len(psh2[Raw])
      # self.seq += len(payloads)
      # return psh1, psh2

      # #THIS WORKS FOR PART G, BUT FOR OUT OF ORDER SEQUENCING. AND THEN THE RECEVING END REASSEMBLES. WIRESHARK SAYS OUT OF ORDER. BUT WORKS.
      # # Step 1: Build the packet for the second part of the payload (out-of-order)
      # # Sending the second portion first, with a higher sequence number
      # psh2 = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq + len(payloads[:6]), ack=self.ack) / payloads[6:]
      # # Step 2: Build the packet for the first part of the payload (arrives after the second part)
      # # This packet is sent with the current sequence number
      # psh1 = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / payloads[:6]
      # # Step 3: Increment the sequence number by the total length of the payload for future packets
      # self.seq += len(payloads)
      # return psh2, psh1  # Send psh2 (out-of-order) first, then psh1

      ############################################################################################################################################################
      # #THIS IS FOR CASE I- BUT OUT OF ORDER SEQUENCING FROM ab, hijkl, cdefg
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/ "ab"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdefg"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+7, ack=self.ack)/"hijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2
   
      # #THIS IS FOR CASE I: DOING 3 PACKETS; ab and cdefg and hijkl BUT IN ORDER
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payloads[:2]
      # self.seq += len(payloads[:2])
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payloads[2:7]
      # self.seq += len(payloads[2:7])
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payloads[7:]
      # self.seq += len(payloads[7:])
      # #self.seq += len(psh1[Raw]) + len(psh2[Raw])
      # #self.seq += len(payloads[:6])
      # return psh1, psh2, psh3

      ############################################################################################################################################################
 
      # #CASE D CASE 0 THIS WORKS: abcd (seq=0), ijkl(seq=8), then cdefgh(seq=2) (just overlapping but no injection)
      # #SURICATA DETECTS THIS CASE
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+8, ack=self.ack)/payloads[8:12]
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/payloads[2:8]
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/payloads[:4]
      # self.seq += len(payloads)
      # return psh2, psh3, psh1

      # #CASE D CASE 1 THIS WORKS: abcd (seq=0), ijkl(seq=8), then  inject (xy)cdefgh(seq=2)
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abcd"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"xyefgh"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+8, ack=self.ack)/"ijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      # # does not reassemble fully; 
      # #CASE D CASE 2: inject ab(xy) (seq=0), ijkl(seq=8), then  cdefgh(seq=2)
      # #right now it reassembles into abxycdefghijkl
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abxy"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdefgh"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+8, ack=self.ack)/"ijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      ############################################################################################################################################################
   
      #CASE J CASE 1: ab, hijkl, cdefgxy 
      # #  reassembly does abcdefghijkl
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"ab"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdefg"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+5, ack=self.ack)/"xyhijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      # #CASE J CASE 2: ab, xyjkl, cdefg
      # #right now, reassembly is abcdexyhijkl 
      # # use this
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"ab"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdexy"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+5, ack=self.ack)/"fghijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      ############################################################################################################################################################

      # #CASE K CASE 1: ab, xh, cdefg, ijkl 
      # # use this
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"ab"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdefg"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"xh"
      # psh4 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+8, ack=self.ack)/"ijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2, psh4

      #CASE K CASE 2: ab, cdef, gy, ijkl 
      # use this
      psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"ab"
      psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdef"
      psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"gy"
      psh4 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+7, ack=self.ack)/"hijkl"
      self.seq += len(payloads)
      return psh1, psh3, psh2, psh4

 

      ############################################################################################################################################################
      ############################ CASES E AND F THAT HAVE 4 SUB-CASES EACH ############################################

      # #CASE E CASE 1: abcd, xyefgh, wzijkl 
      # # reassembly does abcdefgihjkl 
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abcd"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"xyefgh"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"wzijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      # #CASE E CASE 2: abxy, cdefwz, ghijkl
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abxy"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdefwz"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"ghijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      #CASE E CASE 3:  abcd, xyefwz, ghijkl
      # #
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abcd"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"xyefwz"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"ghijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      # #CASE E CASE 4: abxy, cdefgh, wzijkl
      # # USE THIS
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abxy"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+2, ack=self.ack)/"cdefgh"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"wzijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2

      ############################################################################################################################################################

      # #CASE F CASE 1: axy, wzghi, bcdef, jkl
      # # use this
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"axy"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+1, ack=self.ack)/"bcdef"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+4, ack=self.ack)/"wzghi"
      # psh4 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+9, ack=self.ack)/"jkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2, psh4
   
      # #CASE F CASE 2: axy, gwz, bcdef, hijkl
      # # use this
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"axy"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+1, ack=self.ack)/"bcdef"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"gwz"
      # psh4 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+7, ack=self.ack)/"hijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2, psh4

      # #CASE F CASE 3: abc, wzghi, xydef, jkl
      # # use this
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abc"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+1, ack=self.ack)/"xydef"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+4, ack=self.ack)/"wzghi"
      # psh4 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+9, ack=self.ack)/"jkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2, psh4

      # #CASE F CASE 4: abc, gwz, xydef, hijkl
      # # use this
      # psh1 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack)/"abc"
      # psh2 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+1, ack=self.ack)/"xydef"
      # psh3 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+6, ack=self.ack)/"gwz"
      # psh4 = self.ip/TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq+7, ack=self.ack)/"hijkl"
      # self.seq += len(payloads)
      # return psh1, psh3, psh2, psh4



   def send(self, payload):
      psh = self.build(payload)
      ack = sr1(psh, timeout=self._timeout)

      assert ack.haslayer(TCP), 'TCP layer missing'
      assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'
      assert ack[TCP].ack == self.seq , 'Acknowledgment number error'


# Create the session object and connect to host 192.168.13.37 port 80
sess = TcpSession(('192.168.56.103',80))
sess.connect()


#for normal packet with full payload "musubi"
# Build next packet and send it fragmented (layer 2)
p = sess.build("abcdefghijkl")
#TODO LATER: since packets arent this big, this gets rid of the IP Fragmentation. but future: can look into this so its not fragmenting
send(fragment(p, fragsize=1500))
time.sleep(5)
sess.close()



#Direct send data through the session and close
#sess.send("musubi")
#sess.close()

# #Session object can be reusable
# sess.connect()
# sess.send('GET /robot.txt HTTP/1.1\r\n\r\n')
# sess.close()