#!/usr/bin/env python3
"""
Packet Analysis Quiz - An interactive command-line tool for learning network packet analysis.

This script provides a quiz interface for learning and testing knowledge about network packet analysis,
including ARP, ICMP, TCP, and DNS protocols. The quiz presents packet hex dumps and asks questions
about various fields and values within the packets.

Usage:
    python3 packet_quiz.py [-h] [-n NUM_QUESTIONS] [-s START_QUESTION]

Arguments:
    -h, --help            Show this help message and exit
    -n NUM_QUESTIONS, --num-questions NUM_QUESTIONS
                         Number of questions to ask (default: 20)
    -s START_QUESTION, --start-question START_QUESTION
                         Start with a specific question ID

Example:
    # Run quiz with default 20 questions
    python3 packet_quiz.py

    # Run quiz with 10 questions
    python3 packet_quiz.py -n 10

    # Run quiz starting with question ID 5
    python3 packet_quiz.py -s 5

Requirements:
    - Python 3.6 or higher
    - packet_samples.json file in the same directory

The quiz loads packet samples from packet_samples.json and presents questions about various aspects
of network protocols. Each question shows a packet hex dump and highlights relevant bytes when
explaining the answer.
"""

import argparse
import random
import sys
import json
import os

class PacketQuiz:
    """
    A class that implements an interactive packet analysis quiz.

    This class loads packet samples from a JSON file and presents questions about various
    aspects of network protocols including ARP, ICMP, TCP, and DNS. Each question shows
    a packet hex dump and tests understanding of protocol fields and values.

    Attributes:
        num_questions (int): Number of questions to ask in the quiz (default: 20)
        start_question_id (int, optional): Specific question ID to start with
        score (int): Current quiz score
        packet_data (dict): Loaded packet samples from JSON file
        questions (list): List of all available quiz questions

    Example:
        quiz = PacketQuiz(num_questions=10)
        quiz.run_quiz()
    """

    def __init__(self, num_questions=20, start_question_id=None):
        """
        Initialize the PacketQuiz with the specified number of questions.

        Args:
            num_questions (int): Number of questions to ask (default: 20)
            start_question_id (int, optional): Specific question ID to start with
        """
        self.num_questions = num_questions
        self.start_question_id = start_question_id
        self.score = 0
        self.packet_data = self.load_packet_data()
        self.questions = [
            {
                'id': 1,
                'text': "In the ARP Request packet, what is the destination MAC address?",
                'packet_index': 0,
                'options': ["00:1a:2b:3c:4d:5e", "ff:ff:ff:ff:ff:ff", "00:1c:2d:3e:4f:60", "c0:a8:01:02"],
                'answer': "ff:ff:ff:ff:ff:ff",
                'explanation': "ARP requests are broadcast to all devices on the network, so they use the broadcast MAC address ff:ff:ff:ff:ff:ff.",
                'hex_location': "0000 ffffffffffff"
            },
            {
                'id': 2,
                'text': "What is the EtherType value for ARP in the first packet?",
                'packet_index': 0,
                'options': ["0x0800", "0x0806", "0x8035", "0x86DD"],
                'answer': "0x0806",
                'explanation': "0x0806 is the EtherType value that indicates the frame contains an ARP packet.",
                'hex_location': "000c 0806"
            },
            {
                'id': 3,
                'text': "What is the target IP address in the ARP request packet?",
                'packet_index': 0,
                'options': ["192.168.1.1", "192.168.1.2", "8.8.8.8", "93.184.216.34"],
                'answer': "192.168.1.1",
                'explanation': "The target IP (c0:a8:01:01) in the ARP request translates to 192.168.1.1 in dotted decimal notation.",
                'hex_location': "0026 c0a80101"
            },
            {
                'id': 4,
                'text': "True or False: The ARP request packet is asking for the MAC address of 192.168.1.2.",
                'packet_index': 0,
                'options': ["True", "False"],
                'answer': "False",
                'explanation': "The ARP request is asking for the MAC address of 192.168.1.1, not 192.168.1.2. The sender's IP is 192.168.1.2.",
                'hex_location': "0026 c0a80101"
            },
            {
                'id': 5,
                'text': "What is the ARP operation code in the first packet?",
                'packet_index': 0,
                'options': ["0x0001 (Request)", "0x0002 (Reply)", "0x0003 (RARP Request)", "0x0004 (RARP Reply)"],
                'answer': "0x0001 (Request)",
                'explanation': "The operation code 0x0001 indicates this is an ARP request packet.",
                'hex_location': "0014 0001"
            },
            {
                'id': 6,
                'text': "In the ICMP Echo Request packet, what is the destination IP address?",
                'packet_index': 1,
                'options': ["192.168.1.1", "192.168.1.2", "8.8.8.8", "93.184.216.34"],
                'answer': "8.8.8.8",
                'explanation': "The destination IP address in the ICMP packet is 8.8.8.8, which is Google's public DNS server.",
                'hex_location': "001e 08080808"
            },
            {
                'id': 7,
                'text': "What protocol number is used for ICMP in the IP header?",
                'packet_index': 1,
                'options': ["1", "6", "17", "47"],
                'answer': "1",
                'explanation': "Protocol number 1 in the IP header indicates ICMP traffic.",
                'hex_location': "0017 01"
            },
            {
                'id': 8,
                'text': "What is the ICMP type value for an Echo Request?",
                'packet_index': 1,
                'options': ["0", "3", "5", "8"],
                'answer': "8",
                'explanation': "ICMP type 8 indicates an Echo Request (ping), while type 0 would be an Echo Reply.",
                'hex_location': "0022 08"
            },
            {
                'id': 9,
                'text': "True or False: The Time to Live (TTL) value in the ICMP packet is 64.",
                'packet_index': 1,
                'options': ["True", "False"],
                'answer': "False",
                'explanation': "The TTL value in this packet is 4 (0x04), which is typically invalid.",
                'hex_location': "0016 04"
            },
            {
                'id': 10,
                'text': "What is the destination port in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["80", "443", "53", "45678"],
                'answer': "80",
                'explanation': "The destination port is 0x0050 (80 in decimal), which is the standard port for HTTP.",
                'hex_location': "0024 0050"
            },
            {
                'id': 11,
                'text': "What TCP flag is set in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["SYN", "ACK", "FIN", "RST"],
                'answer': "SYN",
                'explanation': "The TCP flags field (0x02) indicates that only the SYN flag is set, which is used to initiate a TCP connection.",
                'hex_location': "002f 02"
            },
            {
                'id': 12,
                'text': "What is the source IP address in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["192.168.1.1", "192.168.1.2", "8.8.8.8", "93.184.216.34"],
                'answer': "192.168.1.2",
                'explanation': "The source IP address (c0:a8:01:02) translates to 192.168.1.2 in dotted decimal notation.",
                'hex_location': "001a c0a80102"
            },
            {
                'id': 13,
                'text': "What is the destination IP address in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["192.168.1.1", "192.168.1.2", "8.8.8.8", "93.184.216.34"],
                'answer': "93.184.216.34",
                'explanation': "The destination IP address (5d:b8:d8:22) translates to 93.184.216.34, which is example.com's IP address.",
                'hex_location': "001e 5db8d822"
            },
            {
                'id': 14,
                'text': "What is the source port in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["80", "443", "53", "45678"],
                'answer': "45678",
                'explanation': "The source port is 0xb25e (45678 in decimal), which is an ephemeral port used by the client.",
                'hex_location': "0022 b25e"
            },
            {
                'id': 15,
                'text': "True or False: The TCP packet with no options contains an HTTP GET request.",
                'packet_index': 2,
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "The payload of the packet contains 'GET / HTTP/1.1' followed by a Host header, which is an HTTP GET request.",
                'hex_location': "0036 47455420202f20485454502f312e31"
            },
            {
                'id': 16,
                'text': "What is the window size in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["4096", "5840", "8192", "32768"],
                'answer': "8192",
                'explanation': "The window size field contains 0x2000, which is 8192 in decimal, indicating the receive buffer size.",
                'hex_location': "0030 2000"
            },
            {
                'id': 17,
                'text': "In the TCP packet with options, what is the data offset value?",
                'packet_index': 3,
                'options': ["5", "8", "10", "12"],
                'answer': "8",
                'explanation': "The data offset value is 8, indicating that the TCP header is 8 × 4 = 32 bytes long, including options.",
                'hex_location': "002e 80"
            },
            {
                'id': 18,
                'text': "What is the IP version used in the TCP packet with options?",
                'packet_index': 3,
                'options': ["IPv4", "IPv6", "IPv5", "IPv4 with extensions"],
                'answer': "IPv4",
                'explanation': "The IP version field in the header is 4 (0x4), indicating this is an IPv4 packet.",
                'hex_location': "000e 4"
            },
            {
                'id': 19,
                'text': "What is the Maximum Segment Size (MSS) value in the TCP packet with options?",
                'packet_index': 3,
                'options': ["1024", "1460", "1500", "9000"],
                'answer': "1024",
                'explanation': "The MSS option value is 0x0400, which is 1024 in decimal.",
                'hex_location': "0038 0400"
            },
            {
                'id': 20,
                'text': "True or False: The TCP packet with options has the ACK flag set.",
                'packet_index': 3,
                'options': ["True", "False"],
                'answer': "False",
                'explanation': "The TCP flags field shows only the CWR (Congestion Window Reduced) flag is set (0x80), not the ACK flag.",
                'hex_location': "002f 80"
            },
            {
                'id': 21,
                'text': "What is the destination port in the UDP/DNS query packet?",
                'packet_index': 4,
                'options': ["53", "80", "443", "67"],
                'answer': "53",
                'explanation': "The destination port is 0x0035 (53 in decimal), which is the standard port for DNS.",
                'hex_location': "0024 0035"
            },
            {
                'id': 22,
                'text': "What is the protocol number for UDP in the IP header?",
                'packet_index': 4,
                'options': ["1", "6", "17", "47"],
                'answer': "17",
                'explanation': "Protocol number 17 in the IP header indicates UDP traffic.",
                'hex_location': "0017 11"
            },
            {
                'id': 23,
                'text': "What domain name is being queried in the DNS packet?",
                'packet_index': 4,
                'options': ["example.com", "google.com", "dns.com", "local.net"],
                'answer': "example.com",
                'explanation': "The DNS query contains the domain name 'example.com' encoded in the DNS message format.",
                'hex_location': "0036 07657861706c6503636f6d00"
            },
            {
                'id': 24,
                'text': "What type of DNS record is being requested in the DNS query?",
                'packet_index': 4,
                'options': ["A", "AAAA", "MX", "TXT"],
                'answer': "TXT",
                'explanation': "The query type is 0x0010, which corresponds to a TXT record request.",
                'hex_location': "0043 0010"
            },
            {
                'id': 25,
                'text': "What is the source port in the UDP/DNS query packet?",
                'packet_index': 4,
                'options': ["53", "49573", "80", "443"],
                'answer': "49573",
                'explanation': "The source port is 0xc1a5 (49573 in decimal), which is an ephemeral port used by the client.",
                'hex_location': "0022 c1a5"
            },
            {
                'id': 26,
                'text': "In the ARP request packet, what is the hardware type value?",
                'packet_index': 0,
                'options': ["0x0001 (Ethernet)", "0x0006 (IEEE 802)", "0x0007 (ARCNET)", "0x000F (Frame Relay)"],
                'answer': "0x0001 (Ethernet)",
                'explanation': "The hardware type value 0x0001 indicates Ethernet, which is the most common hardware type for ARP.",
                'hex_location': "000e 0001"
            },
            {
                'id': 27,
                'text': "What is the protocol type in the ARP request packet?",
                'packet_index': 0,
                'options': ["0x0800 (IPv4)", "0x0806 (ARP)", "0x86DD (IPv6)", "0x8035 (RARP)"],
                'answer': "0x0800 (IPv4)",
                'explanation': "The protocol type 0x0800 indicates IPv4, meaning this ARP request is for an IPv4 address.",
                'hex_location': "0010 0800"
            },
            {
                'id': 28,
                'text': "True or False: In the ARP request packet, the target MAC address is all zeros.",
                'packet_index': 0,
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "In an ARP request, the target MAC is unknown and is set to all zeros (000000000000).",
                'hex_location': "0020 000000000000"
            },
            {
                'id': 29,
                'text': "What is the hardware size value in the ARP request packet?",
                'packet_index': 0,
                'options': ["4", "6", "8", "10"],
                'answer': "6",
                'explanation': "The hardware size is 6 bytes, which is the standard length of a MAC address.",
                'hex_location': "0012 06"
            },
            {
                'id': 30,
                'text': "What is the protocol size value in the ARP request packet?",
                'packet_index': 0,
                'options': ["2", "4", "6", "8"],
                'answer': "4",
                'explanation': "The protocol size is 4 bytes, which is the standard length of an IPv4 address.",
                'hex_location': "0013 04"
            },
            {
                'id': 31,
                'text': "In the ICMP Echo Request packet, what is the identification field value in the IP header?",
                'packet_index': 1,
                'options': ["0x0102", "0x0000", "0x4001", "0xf77c"],
                'answer': "0x0102",
                'explanation': "The identification field in the IP header is 0x0102, used to identify fragments of the original datagram.",
                'hex_location': "0012 0102"
            },
            {
                'id': 32,
                'text': "What is the ICMP code value in the Echo Request packet?",
                'packet_index': 1,
                'options': ["0", "1", "3", "8"],
                'answer': "0",
                'explanation': "The ICMP code for Echo Request is 0, which provides additional context for the ICMP type.",
                'hex_location': "0023 00"
            },
            {
                'id': 33,
                'text': "What is the total length of the IP packet in the ICMP Echo Request?",
                'packet_index': 1,
                'options': ["60", "64", "84", "100"],
                'answer': "60",
                'explanation': "The total length field in the IP header is 0x003c, which is 60 bytes in decimal.",
                'hex_location': "0010 003c"
            },
            {
                'id': 34,
                'text': "True or False: The ICMP Echo Request packet has the Don't Fragment (DF) bit set.",
                'packet_index': 1,
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "The flags field in the IP header has the DF bit set (0x4000), indicating the packet should not be fragmented.",
                'hex_location': "0014 4000"
            },
            {
                'id': 35,
                'text': "What is the ICMP sequence number in the Echo Request packet?",
                'packet_index': 1,
                'options': ["4096", "2048", "1024", "8192"],
                'answer': "4096",
                'explanation': "The ICMP sequence number is 0x1000, which is used to match Echo Requests with their corresponding Echo Replies.",
                'hex_location': "0028 1000"
            },
            {
                'id': 36,
                'text': "In the TCP packet with no options, what is the IP header length?",
                'packet_index': 2,
                'options': ["20 bytes", "24 bytes", "28 bytes", "32 bytes"],
                'answer': "20 bytes",
                'explanation': "The IP header length is 5 words (5 × 4 = 20 bytes), which is the standard length without IP options.",
                'hex_location': "000e 45"
            },
            {
                'id': 37,
                'text': "What is the acknowledgment number in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["0", "1", "1000", "65535"],
                'answer': "0",
                'explanation': "The acknowledgment number is 0x00000000, which is expected for the first packet in a TCP handshake.",
                'hex_location': "002a 00000000"
            },
            {
                'id': 38,
                'text': "True or False: The TCP packet with no options has the PSH flag set.",
                'packet_index': 2,
                'options': ["True", "False"],
                'answer': "False",
                'explanation': "The TCP flags field shows only the SYN flag is set (0x02), not the PSH flag.",
                'hex_location': "002f 02"
            },
            {
                'id': 39,
                'text': "What is the urgent pointer value in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["0", "1", "16", "32"],
                'answer': "0",
                'explanation': "The urgent pointer is 0x0000, which is not used since the URG flag is not set.",
                'hex_location': "0034 0000"
            },
            {
                'id': 40,
                'text': "What is the total length of the IP packet in the TCP packet with no options?",
                'packet_index': 2,
                'options': ["40", "48", "60", "72"],
                'answer': "72",
                'explanation': "The total length field in the IP header is 0x0048, which is 72 bytes in decimal.",
                'hex_location': "0010 0048"
            },
            {
                'id': 41,
                'text': "In the TCP packet with options, what is the window scale value?",
                'packet_index': 3,
                'options': ["1", "3", "7", "8"],
                'answer': "8",
                'explanation': "The window scale has a value of 8, which means the actual window size is shifted left by 3 bits (multiplied by 8).\n01 NOP, 03 Window kind, 03 Length, 08 Value",
                'hex_location': "003b 01030308"
            },
            {
                'id': 42,
                'text': "What is the timestamp value in the TCP packet with options?",
                'packet_index': 3,
                'options': ["0x012c3d4e", "0x00000000", "0x01030308", "0x02040405"],
                'answer': "0x012c3d4e",
                'explanation': "The timestamp value is 0x012c3d4e, which is used for round-trip time measurement and protection against wrapped sequence numbers.",
                'hex_location': "0045 012c3d4e"
            },
            {
                'id': 43,
                'text': "True or False: The TCP packet with options has a larger header than the TCP packet without options.",
                'packet_index': 3,
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "The TCP packet with options has a data offset of 8 (32 bytes), while the packet without options has a data offset of 5 (20 bytes).",
                'hex_location': "002f 80"
            },
            {
                'id': 44,
                'text': "What is the total length of the IP packet in the TCP packet with options?",
                'packet_index': 3,
                'options': ["60", "72", "84", "92"],
                'answer': "92",
                'explanation': "The total length field in the IP header is 0x005c, which is 92 bytes in decimal.",
                'hex_location': "0010 005c"
            },
            {
                'id': 45,
                'text': "What is the echo timestamp reply value in the TCP packet with options?",
                'packet_index': 3,
                'options': ["0x4e000000", "0x012c3d4e", "0x01030308", "0x02040405"],
                'answer': "0x4e000000",
                'explanation': "The echo timestamp reply value is 0x4e000000, indicating this is the first packet in the connection with no previous timestamp to echo.",
                'hex_location': "0048 4e000000"
            },
            {
                'id': 46,
                'text': "In the UDP/DNS query packet, what is the UDP length?",
                'packet_index': 4,
                'options': ["8", "16", "28", "40"],
                'answer': "40",
                'explanation': "The UDP length field is 0x0028, which is 40 bytes in decimal, including the 8-byte UDP header and 32-byte DNS payload.",
                'hex_location': "0026 0028"
            },
            {
                'id': 47,
                'text': "What is the DNS transaction ID in the UDP/DNS query packet?",
                'packet_index': 4,
                'options': ["0x0123", "0xa123", "0xbb23", "0xb123"],
                'answer': "0x0123",
                'explanation': "The DNS transaction ID is 0x0123, which is used to match queries with their corresponding responses.",
                'hex_location': "002a 0123"
            },
            {
                'id': 48,
                'text': "True or False: The DNS query in the UDP packet is requesting an authoritative answer.",
                'packet_index': 4,
                'options': ["True", "False"],
                'answer': "False",
                'explanation': "The DNS flags field does not have the AA (Authoritative Answer) bit set, as this is a query, not a response.",
                'hex_location': "002c 0100"
            },
            {
                'id': 49,
                'text': "How many questions are included in the DNS query packet?",
                'packet_index': 4,
                'options': ["0", "1", "2", "4"],
                'answer': "1",
                'explanation': "The questions count field in the DNS header is 0x0001, indicating there is one question in the query.",
                'hex_location': "002e 0001"
            },
            {
                'id': 50,
                'text': "What is the DNS query class in the UDP/DNS query packet?",
                'packet_index': 4,
                'options': ["IN (Internet)", "CH (Chaos)", "HS (Hesiod)", "ANY"],
                'answer': "IN (Internet)",
                'explanation': "The query class is 0x0001, which corresponds to IN (Internet), the most common DNS class used for Internet resources.",
                'hex_location': "0045 0001"
            }
        ]
    
    def load_packet_data(self, filename='packet_samples.json'):
        """
        Load packet data from a JSON file.

        Args:
            filename (str): Path to the JSON file containing packet samples (default: 'packet_samples.json')

        Returns:
            dict: Loaded packet data containing packet samples and their metadata

        Raises:
            SystemExit: If the file is not found or contains invalid JSON
        """
        try:
            with open(filename, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: File '{filename}' contains invalid JSON.")
            sys.exit(1)
    
    def format_hex_dump(self, hex_string, offset=None, num_bytes=None):
        """
        Format a hex string with 16 bytes per line, spaces between bytes, and line numbers.
        Optionally highlights specific bytes in the hex dump.
        
        Args:
            hex_string (str): The hex string to format
            offset (int, optional): Starting byte position to highlight
            num_bytes (int, optional): Number of bytes to highlight

        Returns:
            str: Formatted hex dump with line numbers and optional highlighting
        """
        formatted_lines = []
        
        # ANSI color codes
        HIGHLIGHT_COLOR = '\033[1;32m'  # Bright green
        RESET_COLOR = '\033[0m'        # Reset to default
        
        # Process the hex string in chunks of 32 characters (16 bytes)
        for i in range(0, len(hex_string), 32):
            # Get the current chunk (up to 32 characters)
            chunk = hex_string[i:i+32]
            
            # Calculate the line number (0000, 0010, 0020, etc.)
            line_number = f"{i//2:04x}"  # Convert byte position to hex
            
            # Format the chunk with spaces between each byte (2 hex characters)
            formatted_bytes = []
            for j in range(0, len(chunk), 2):
                byte_pos = (i + j) // 2  # Calculate the byte position
                byte = chunk[j:j+2]
                
                # Check if this byte should be highlighted
                if offset is not None and num_bytes is not None:
                    if offset <= byte_pos < offset + num_bytes:
                        formatted_bytes.append(f"{HIGHLIGHT_COLOR}{byte}{RESET_COLOR}")
                    else:
                        formatted_bytes.append(byte)
                else:
                    formatted_bytes.append(byte)
            
            # Join the bytes with spaces
            formatted_line = ' '.join(formatted_bytes)
            
            # Add the line number and formatted bytes to the result
            formatted_lines.append(f"{line_number}  {formatted_line}")
        
        return '\n'.join(formatted_lines)
    
    def run_quiz(self):
        """
        Run the packet analysis quiz.

        This method:
        1. Displays quiz introduction
        2. If start_question_id is provided, starts with that specific question
        3. Presents each question with a packet hex dump
        4. Accepts and validates user answers
        5. Provides feedback and explanations
        6. Shows final score upon completion

        The quiz shows packet hex dumps and highlights relevant bytes when explaining answers.
        Users can answer with either the letter option (A, B, C, D) or the exact answer text.
        """
        print("\n===== Packet Analysis Quiz =====")
        print(f"Number of questions: {self.num_questions}")
        print("================================\n")
        
        # If start_question_id is provided, find that question and put it first
        if self.start_question_id is not None:
            # Find the question with the specified ID
            start_question = None
            remaining_questions = []
            
            for question in self.questions:
                if question['id'] == self.start_question_id:
                    start_question = question
                else:
                    remaining_questions.append(question)
            
            if start_question:
                # Shuffle the remaining questions
                random.shuffle(remaining_questions)
                # Put the start question first, followed by shuffled remaining questions
                quiz_questions = [start_question] + remaining_questions[:self.num_questions - 1]
                print(f"Starting with question ID: {self.start_question_id}")
            else:
                print(f"Question ID {self.start_question_id} not found. Starting with random questions.")
                # Shuffle questions and take the requested number
                random.shuffle(self.questions)
                quiz_questions = self.questions[:self.num_questions]
        else:
            # Original behavior: shuffle all questions and take the requested number
            random.shuffle(self.questions)
            quiz_questions = self.questions[:self.num_questions]
        
        for i, question in enumerate(quiz_questions):
            print(f"\nQuestion {i+1}/{self.num_questions} [ID: {question['id']}]:")
            print(question['text'])
            
            # Display the packet hex dump
            packet = self.packet_data['packets'][question['packet_index']]
            print(f"\nPacket: {packet['name']}")
            print(f"Hex Dump:")
            formatted_dump = self.format_hex_dump(packet['hex_dump'])
            print(formatted_dump)
            
            # Display options
            for j, option in enumerate(question['options']):
                print(f"  {chr(65+j)}) {option}")
            
            # Get user answer
            user_answer = input("\nYour answer: ").strip()
            
            # Convert letter answer to the actual option
            correct_answer = question['answer']
            user_option = ""
            
            if user_answer.upper() in ['A', 'B', 'C', 'D']:
                index = ord(user_answer.upper()) - ord('A')
                if 0 <= index < len(question['options']):
                    user_option = question['options'][index]
            else:
                user_option = user_answer
            
            # Check answer
            is_correct = self.check_answer(user_option, correct_answer)
            
            if is_correct:
                print("\n✓ Correct!")
                self.score += 1
            else:
                print(f"\n✗ Incorrect. The correct answer is: {correct_answer}")
            
            # Display the packet hex dump again with highlighting for the relevant bytes
            print(f"\nPacket: {packet['name']}")
            print(f"Hex Dump:")
            
            # Parse hex_location to get offset and num_bytes for highlighting
            hex_location = question.get('hex_location', '')
            offset = None
            num_bytes = None
            
            if hex_location:
                try:
                    parts = hex_location.split()
                    if len(parts) >= 2:
                        # Convert the offset from hex string to integer
                        offset = int(parts[0], 16)
                        # Calculate number of bytes from the hex data
                        hex_data = parts[1]
                        num_bytes = len(hex_data) // 2
                except ValueError:
                    # If there's any error parsing, don't highlight
                    pass
            
            formatted_dump = self.format_hex_dump(packet['hex_dump'], offset, num_bytes)
            print(formatted_dump)
            
            # Show explanation
            print(f"Explanation: {question.get('explanation', 'No explanation available.')}")
            print(f"Relevant hex bytes: {question.get('hex_location', 'Not specified')}")
            
            # Wait for user to continue
            input("\nPress Enter to continue...")
        
        # Show final score
        print("\n===== Quiz Complete =====")
        print(f"Your score: {self.score}/{self.num_questions} ({self.score/self.num_questions*100:.1f}%)")
        print("========================\n")
    
    def check_answer(self, user_answer, correct_answer):
        """
        Check if the user's answer is correct.

        This method handles various answer formats:
        - Direct string matches (case-insensitive)
        - True/False answers (accepts 't'/'f' shortcuts)
        - Hex values (e.g., '0x0806' matches '0x0806')

        Args:
            user_answer (str): The answer provided by the user
            correct_answer (str): The expected correct answer

        Returns:
            bool: True if the answer is correct, False otherwise
        """
        # Remove whitespace and convert to lowercase
        user_answer = user_answer.lower().strip()
        correct_answer = correct_answer.lower().strip()
        
        # Direct match
        if user_answer == correct_answer:
            return True
        
        # Handle true/false
        if correct_answer in ['true', 'false'] and user_answer in ['true', 'false', 't', 'f']:
            if user_answer == 't':
                user_answer = 'true'
            elif user_answer == 'f':
                user_answer = 'false'
            return user_answer == correct_answer
        
        # Handle hex values
        if correct_answer.startswith('0x') and user_answer.startswith('0x'):
            try:
                return int(correct_answer, 16) == int(user_answer, 16)
            except ValueError:
                return False
        
        return False

def main():
    """
    Main entry point for the Packet Analysis Quiz.

    This function:
    1. Sets up command-line argument parsing
    2. Creates a PacketQuiz instance with user-specified options
    3. Runs the quiz
    4. Handles keyboard interrupts gracefully
    """
    parser = argparse.ArgumentParser(description='Packet Analysis Quiz')
    parser.add_argument('-n', '--num-questions', type=int, default=20,
                        help='Number of questions (default: 20)')
    parser.add_argument('-s', '--start-question', type=int,
                        help='Start with a specific question ID')
    
    args = parser.parse_args()
    
    quiz = PacketQuiz(num_questions=args.num_questions, start_question_id=args.start_question)
    quiz.run_quiz()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nQuiz terminated by user.")
        sys.exit(0)
