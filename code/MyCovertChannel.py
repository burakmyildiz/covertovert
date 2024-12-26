import time
from random import randint
import scapy.all
from scapy.all import IP, UDP, Raw, sniff, Ether
from CovertChannelBase import CovertChannelBase


"""
Implementation of a Covert Storage Channel that exploits 
the UDP destination port field for covert communication.

This file contains a single class: MyCovertChannel, which 
inherits from CovertChannelBase. It must have two methods:
  - send(...)    : The covert sender
  - receive(...) : The covert receiver

All numeric thresholds, port ranges, etc. are taken as 
parameters (passed in from config.json), ensuring a 
parametric implementation.

IMPORTANT:
- Do NOT change the name of this file or this class.
- Do NOT remove or rename the send(...) and receive(...) methods.
- Additional helper methods are allowed.
- Use self.send(...) instead of scapy.send(...) directly.

Author: Burak Muammer Yıldız / Group 49 / Student ID: 2529451
Date:   26.12.2024
"""

class MyCovertChannel(CovertChannelBase):
    """
    MyCovertChannel implements a covert storage channel 
    by manipulating the UDP destination port to encode 
    one or more bits per packet.

    The covert channel logic is:

    - We take each bit of the message, then:
      * If bit == 0, we pick a random port in [rangeA_min, rangeA_max].
      * If bit == 1, we pick a random port in [rangeB_min, rangeB_max].
      (Or any other indirect mapping you choose, as long as it is consistent for sender and receiver.)

    - The receiver sniffs incoming packets, extracts the 
      destination port, and decides if it belongs to range A (decode 0)
      or range B (decode 1). 

    - The special stop character '.' indicates the end of 
      covert communication. As soon as the receiver decodes 
      '.', it stops capturing packets.
    """

    def __init__(self):
        """
        Initializes the MyCovertChannel instance by calling 
        the parent (CovertChannelBase) constructor. This ensures
        that any base class functionality (e.g., logging, random 
        message generation, etc.) is properly set up.
        """
        super().__init__()
    def send(
        self,
        rangeA_min,
        rangeA_max,
        rangeB_min,
        rangeB_max,
        bits_per_character,
        log_file_name,
        dst_ip,
        udp_sport,
        **kwargs
    ):
        """
        The covert channel sender logic. This function is triggered 
        by 'make send' -> run.py -> MyCovertChannel.send(...)
        with the parameters from config.json.

        Parameters
        ----------
        rangeA_min : int
            Minimum port number for range A (decodes to '0').
        rangeA_max : int
            Maximum port number for range A (decodes to '0').
        rangeB_min : int
            Minimum port number for range B (decodes to '1').
        rangeB_max : int
            Maximum port number for range B (decodes to '1').
        bits_per_character : int
            How many bits form one character (commonly 8 for ASCII).
        log_file_name : str
            Where to log the sent message for debugging/comparison.
        dst_ip : str
            Destination IP for packets (your receiver container). 
            Default is "172.18.0.3" for the receiver container IP.
        udp_sport : int
            The UDP source port used in the scapy packet.
        **kwargs : dict
            Any other parameters from config.json (not used here).
        """

        # 1. Create a random message (excluding the '.' character).
        #    The base class ensures '.' is not used in random messages.
        #    We can optionally set min/max length, or rely on defaults.
        #    Example: to measure capacity with 16 ASCII chars → 128 bits
        message = self.generate_random_message(min_length=16, max_length=16)

        # 2. Log the message before sending (for later comparison).
        self.log_message(message, log_file_name)

        # 3. Convert the entire message into bits (string of '0'/'1').
        #    For ASCII: each char is typically 8 bits.
        bits_to_send = self._message_to_bits(message, bits_per_character)

        # 4. We can start a timer if you'd like to measure capacity here.
        #    We could measure time externally, however, this is more accurate:
        start_time = time.time()

        # 5. Send each bit by constructing a packet with a chosen 'dport'.
        for bit in bits_to_send:
            # Choose a random port in the correct range:
            if bit == '0':
                chosen_port = randint(rangeA_min, rangeA_max)
            else:
                chosen_port = randint(rangeB_min, rangeB_max)

            # Create a scapy packet. Use IP/UDP. 
            # The actual payload is irrelevant in covert channels, but we can add something minimal.
            pkt = IP(dst=dst_ip) / UDP(sport=udp_sport, dport=chosen_port) / Raw(load=b"send")

            # Send the packet using the base class's send() method!
            CovertChannelBase.send(self, pkt)

        # 6. Send a stopping packet (the '.' character).
        #    We'll encode '.' as we do for normal chars, 
        #    but that character signals the receiver to stop.
        stop_bits = self._char_to_bits('.', bits_per_character)
        for bit in stop_bits:
            if bit == '0':
                chosen_port = randint(rangeA_min, rangeA_max)
            else:
                chosen_port = randint(rangeB_min, rangeB_max)

            pkt = IP(dst=dst_ip) / UDP(sport=udp_sport, dport=chosen_port) / Raw(load=b"stop")
            CovertChannelBase.send(self, pkt)

        # 7. Stop the timer right after sending the last packet.
        end_time = time.time()
        elapsed = end_time - start_time

        # 8. Detailed timing and bit counts.
        total_message_bits = len(bits_to_send)  # Message bits only
        total_stop_bits = bits_per_character     # Stop character bits
        total_transmitted_bits = total_message_bits + total_stop_bits

        # We can print the time to get an idea of capacity. 
        # Also we included this in our README.md as well.
        print(f"[Sender] Sent a total of {total_transmitted_bits} bits:")
        print(f"         - Message bits: {total_message_bits}")
        print(f"         - Stop character bits: {total_stop_bits}")
        print(f"[Sender] Transmission time: {elapsed:.3f} seconds.")
        print(f"[Sender] Capacity: {total_transmitted_bits / elapsed:.3f} bits/second.")
        print("[Sender] Finished sending covert message!")
        # At this point, the sender finished sending covert message.

        
    def receive(
        self,
        rangeA_min,
        rangeA_max,
        rangeB_min,
        rangeB_max,
        bits_per_character,
        log_file_name,
        sniff_filter,
        **kwargs
    ):
        """
        The covert channel receiver logic. This function is triggered 
        by 'make receive' -> run.py -> MyCovertChannel.receive(...)
        with the parameters from config.json.

        Parameters
        ----------
        rangeA_min : int
            Minimum port number for range A (decodes to '0').
        rangeA_max : int
            Maximum port number for range A (decodes to '0').
        rangeB_min : int
            Minimum port number for range B (decodes to '1').
        rangeB_max : int
            Maximum port number for range B (decodes to '1').
        bits_per_character : int
            How many bits form one character (commonly 8 for ASCII).
        log_file_name : str
            Where to log the received (decoded) message.
        sniff_filter : str
            A BPF filter for sniffing (default is "udp").
        **kwargs : dict
            Any other parameters from config.json (not used here).
        """

        # We'll accumulate bits here until we form characters.
        self.received_bits_buffer = ""
        self.decoded_message = ""

        # We define an inner callback to handle each captured packet
        def pkt_handler(pkt):
            # Check if it has a UDP layer
            if UDP in pkt:
                dport = pkt[UDP].dport

                # Decode the bit according to the port ranges
                if rangeA_min <= dport <= rangeA_max:
                    bit = '0'
                elif rangeB_min <= dport <= rangeB_max:
                    bit = '1'
                else:
                    # If a port is outside the known ranges,
                    # we ignore it or handle as error
                    return

                # We add the bit to our buffer
                self.received_bits_buffer += bit

                # Check if we have enough bits to form a character
                if len(self.received_bits_buffer) >= bits_per_character:
                    # Extract the first 'bits_per_character' bits
                    bits_chunk = self.received_bits_buffer[:bits_per_character]
                    # Remove them from the buffer
                    self.received_bits_buffer = self.received_bits_buffer[bits_per_character:]

                    # Convert bits to a character
                    c = self._bits_to_char(bits_chunk)

                    # If it is the stop character '.', stop sniffing
                    if c == '.':
                        self.decoded_message += c
                        sniff_session.stop()  # type: ignore
                        return
                    else:
                        # We append to decoded_message
                        self.decoded_message += c

        print("[Receiver] Start sniffing...")
        # We invoke scapy's sniff function. We store the session in a variable
        # so that we can call sniff_session.stop() when '.' is detected.
        sniff_session = sniff(
            filter=sniff_filter,
            prn=pkt_handler,
            store=False  # We do not store packets in memory, we only decode on-the-fly
        )

        # Once sniff returns, we've either timed out or encountered stop '.' 
        # in the callback. 
        print("[Receiver] Finished sniffing.")
        print(f"[Receiver] Decoded message: {self.decoded_message}")

        # Log the decoded message in the specified file
        self.log_message(self.decoded_message, log_file_name)

    # Helper methods
    def _message_to_bits(self, message, bits_per_char=8):
        bit_string = ""
        for c in message:
            bit_string += self._char_to_bits(c, bits_per_char)
        return bit_string

    def _char_to_bits(self, c, bits_per_char=8):
        ascii_val = ord(c)
        return format(ascii_val, '0{}b'.format(bits_per_char))[-bits_per_char:]

    def _bits_to_char(self, bit_string):
        val = int(bit_string, 2)
        return chr(val)
