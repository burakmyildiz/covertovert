#  Covert Storage Channel that exploits Protocol Field Manipulation using Destination Port field in UDP [Code: CSC-PSV-UDP-SP]

  

**Authors**: Burak Muammer Yıldız, Group 49

  

##  1. Overview

  

This project implements a **Covert Storage Channel** by **manipulating the UDP destination port** field.

A covert channel is a hidden communication path that bypasses standard security controls. Here, we send bits of data by carefully choosing UDP port numbers in two distinct ranges (Range A for `0` bits, Range B for `1` bits).

The receiver sniffs inbound packets, inspects the port, and reconstructs the hidden message.

  

##  2. Motivation and Summary

  

-  **Why I chose UDP Destination Port?** Because it is a 16-bit field that many intrusion detection systems may overlook if the ports appear "valid" or random. We only need two subranges of possible port values to transmit bits.

-  **How is Data Encoded?** Each bit is encoded by choosing a UDP destination port within a certain range.

	We define `[rangeA_min, rangeA_max]` to represent a `0` bit, and `[rangeB_min, rangeB_max]` to represent a `1`.

-  **Stop Character:** A `'.'` (dot) character signals the receiver to stop sniffing, ensuring we know where the hidden message ends.

  

##  3. Implementation Details

  

###  3.1 Sender Logic

  

1.  **Random Message Generation:**

	The sender generates a random message of 16 ASCII characters (by default). We exclude the `'.'` character.

2.  **Bit Conversion:**

	We convert each character to its 8-bit ASCII representation. Thus, a 16-character message corresponds to 128 bits.

3.  **Port Selection:**

-  For `0` bits, pick a random port in `[rangeA_min, rangeA_max]`.

-  For `1` bits, pick a random port in `[rangeB_min, rangeB_max]`.

4.  **Packet Transmission:**

	We construct a scapy packet: `IP(dst=dst_ip) / UDP(sport=udp_sport, dport=chosen_port) / Raw(load="...")`.

	Then we call the **base**  `send(...)` from `CovertChannelBase` using `CovertChannelBase.send(pkt)`.

5.  **Stop Character:**

	After sending the entire message, we encode the stop character `'.'` in the same manner. The receiver detects this and terminates capturing.

  

###  3.2 Receiver Logic

  

1.  **Sniffing:**

	We use `scapy.sniff()` with a filter (e.g. `"udp"`) to capture packets.

2.  **Bit Decoding:**

	For each packet, we read the `UDP.dport`:

	If it’s within `[rangeA_min, rangeA_max]`, we decode `0`.
	Else if it’s within `[rangeB_min, rangeB_max]`, we decode `1`.

3.  **Character Reconstruction:**

	Every time we accumulate `bits_per_character` bits (typically 8), we convert them to a character.

4.  **Stop Condition:**

	If the character is `'.'`, we stop sniffing. Otherwise, we append it to the decoded message.

  

###  3.3 Parameter Constraints

  
|Parameter|  Description| Possible Range & Note |
|--|--|--|--|
| `rangeA_min`/`max` | Port range for bit `0`  | Must be valid UDP ports (1–65535), and not overlap with `rangeB`.  |
| `rangeB_min`/`max`| Port range for bit `1` | Must be valid UDP ports, distinct from `rangeA`.|
|  `bits_per_character`  | How many bits form one char (8 for ASCII). | Typically `8`, but we can set `7`, `9`, etc. |
|  `dst_ip`  | Destination IP for the receiver container | Must match the static IP in `docker-compose.yaml`. |
|  `udp_sport`  | Source port for the packets | Arbitrary, but it could also be based on your network policy. |
|  `sniff_filter`  | BPF filter for capturing traffic | Typically `"udp"`; can be refined if desired. |

  

###  3.4 Limitations / Observations

-  **Port Overlaps**: We need to ensure `[rangeA_min, rangeA_max]` does not overlap `[rangeB_min, rangeB_max]`, or decoding will be ambiguous.

-  **Stop Character Loss**: If the final packet carrying `'.'` is dropped, the receiver will keep sniffing.

  

##  4. Usage and Setup

  

1.  **Build and Run Containers**

	Make sure your `docker-compose.yaml` defines a `sender` and `receiver` service. Run:
	```bash
	docker-compose up --build
	```
2.  **Access Containers**
   -   **Sender** container: `docker exec -it sender bash`
    -   **Receiver** container: `docker exec -it receiver bash`
3.  **Receive First**  
    In the receiver container:
    
    ```bash
    make receive 
    ```
    This will start sniffing.
4.  **Send**  
    In the sender container:
    
    ```bash
    make send
    ```
    
    It generates a random message, sends packets, and logs the message.
5.  **Compare**  
    After both finish, you can compare logs with:
    
    ```bash
    make compare
    ```
    
    If the logs match, you have successfully transferred the covert message.

## 5. Measuring Covert Channel Capacity

We measure capacity in **bits per second**. Follow these steps:

1.  **Fix Message Size**: We used a 16-character ASCII message → 16 × 8 = 128 bits.
2. **Add Stop Character**: The stop character (`.`) adds an extra 8 bits.
3.  **Start Timer**: Just before sending the first bit, we note `start_time`.
4.  **Stop Timer**: Right after sending the final (stop) bit, record `end_time`.
5.  **Compute Capacity**: 
	Capacity = Total Bits Sent / (end_time - start_time) 
	where: 
	- **Total Bits Sent** = Message Bits + Stop Character Bits.
	
### 5.1 Our Observed Capacity

In our local tests with Docker containers, we observed the following:

-   **Time**: ~3.9 seconds to send 128 message bits and 8 stop character bits
-   **Capacity**: ~35 bits/sec

>Note that depending on your host and Docker network performance, you might achieve higher or lower capacity. 

## 6. Repository Link

Our public repository (forked from the original `covertovert`) for Phase 2 is available on the `phase2` branch: [**GitHub Repository - Phase 2**](https://github.com/burakmyildiz/covertovert/tree/phase2)

Inside this repository's `code` folder, you will find:

-   `MyCovertChannel.py`
-   `config.json`
-   `Makefile`
-   `run.py`
-   `README.md` (this file)
-   Sphinx docs (in `docs/` folder).

## 7. Conclusion

By leveraging unused bits in the UDP destination port field, we have demonstrated how to create a **covert storage channel**. This channel can be difficult to detect if ports are chosen to appear innocuous. We have also shown how to measure capacity and provided details on usage, limitations, and potential improvements.