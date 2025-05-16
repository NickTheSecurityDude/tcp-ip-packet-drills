# Network Protocol Quiz Applications

A hands-on learning toolkit built for students and professionals diving deep into network packet analysis and TCP behavior. This project was born from my own study of packet capture analysis and threat detection as part of a **SANS Cyber Security degree**. While working through the material, I found it challenging to locate high-quality, interactive resources that taught these concepts visually and practically — with enough repetition and real-world examples to truly master them.

To solve that, I created these command-line quiz applications to make network protocol learning more intuitive and less abstract. They’re designed for **cybersecurity students and SOC analysts** who want to strengthen their skills in hex dump interpretation, protocol behavior, and `tcpdump`-level packet inspection. I used **generative AI** throughout the process to help generate targeted questions, break down complex packet logic, and structure the content in a way that makes difficult topics approachable and engaging.

Though built to support my own learning, these tools are meant to be shared — I hope others in the community can benefit from them too. They're particularly useful for those using tools like **tcpdump** or **Wireshark** and seeking to better understand what they're seeing at the byte level.

## Overview

This repository contains two complementary quiz applications:

1. **Packet Analysis Quiz** - Test your knowledge of network packet structures, protocols, and hex dump analysis
2. **TCP Flags Quiz** - Master TCP flags, their hex values, and tcpdump filter expressions

These quizzes provide hands-on practice with real-world networking concepts that are essential for network troubleshooting, security analysis, and certification exam preparation.

## Installation

### Prerequisites

- Python 3.6 or higher

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/network-protocol-quizzes.git](https://github.com/NickTheSecurityDude/tcp-ip-packet-drills.git
   cd tcp-ip-packet-drills
   ```

2. No additional installation steps are required as the applications use only Python standard library modules.

## Usage

### Packet Analysis Quiz

The Packet Analysis Quiz presents packet hex dumps and asks questions about various fields and values within the packets, covering ARP, ICMP, TCP, and DNS protocols.

```bash
# Run quiz with default 20 questions
python3 packet_quiz.py

# Run quiz with 10 questions
python3 packet_quiz.py -n 10

# Run quiz starting with question ID 5
python3 packet_quiz.py -s 5
```

### TCP Flags Quiz

The TCP Flags Quiz tests your knowledge of TCP flags, their hex values, and how to filter them using tcpdump expressions.

```bash
# Run quiz with default 20 questions
python3 tcp_flags_quiz.py

# Run quiz with 10 questions
python3 tcp_flags_quiz.py -n 10
```

## Quiz Content

### Packet Analysis Quiz

This quiz covers:

- **ARP Protocol** - Hardware types, operation codes, address resolution
- **ICMP Protocol** - Echo requests/replies, types, codes
- **TCP Protocol** - Header fields, flags, options, sequence numbers
- **DNS Protocol** - Query types, record formats, domain name encoding
- **Hex Dump Analysis** - Reading and interpreting packet hex dumps
- **Protocol Fields** - Identifying and understanding protocol-specific fields

The quiz displays actual packet hex dumps and highlights relevant bytes when explaining answers, providing a practical learning experience.

### TCP Flags Quiz

This quiz covers:

- **TCP Flag Values** - Individual flag hex values (SYN, ACK, FIN, RST, PSH, URG)
- **Flag Combinations** - Common combinations like SYN+ACK, FIN+ACK
- **tcpdump Filters** - Writing and understanding tcpdump expressions
- **TCP Connection States** - Understanding the TCP state machine
- **Packet Filtering** - Techniques for filtering network traffic

## Command-line Options

### Packet Analysis Quiz

```
usage: packet_quiz.py [-h] [-n NUM_QUESTIONS] [-s START_QUESTION]

options:
  -h, --help            show this help message and exit
  -n NUM_QUESTIONS, --num-questions NUM_QUESTIONS
                        Number of questions (default: 20)
  -s START_QUESTION, --start-question START_QUESTION
                        Start with a specific question ID
```

### TCP Flags Quiz

```
usage: tcp_flags_quiz.py [-h] [-n NUM_QUESTIONS]

options:
  -h, --help            show this help message and exit
  -n NUM_QUESTIONS, --num-questions NUM_QUESTIONS
                        Number of questions (default: 20)
```

## Sample Output

### Packet Analysis Quiz

When running the Packet Analysis Quiz, you'll see output similar to this:

```
===== Packet Analysis Quiz =====
Number of questions: 20
================================

Question 1/20 [ID: 15]:
True or False: The TCP packet with no options contains an HTTP GET request.

Packet: TCP Packet (No Options)
Hex Dump:
0000  00 1a 2b 3c 4d 5e 00 1c 2d 3e 4f 60 08 00 45 00 
...

  A) True
  B) False

Your answer: 
```

The quiz will show a packet hex dump, ask a question, and provide multiple-choice answers. After answering, it will explain the correct answer and highlight the relevant bytes in the hex dump.

### TCP Flags Quiz

When running the TCP Flags Quiz, you'll see output similar to this:

```
===== TCP Flags Quiz =====
Number of questions: 20
===========================

Question 1/20 [ID: 10]:
Which hex value matches SYN+ACK?

  A) 0x02
  B) 0x12
  C) 0x10
  D) 0x04

Your answer: 
```

After answering, the quiz will provide feedback and an explanation of the correct answer.

## Dependencies

These applications use only Python standard library modules:
- `argparse` - For command-line argument parsing
- `random` - For question randomization
- `sys` - For system operations
- `json` - For parsing packet data (packet_quiz.py only)
- `os` - For file operations (packet_quiz.py only)

No external dependencies or installations are required.

## Reporting Bugs or Incorrect Answers

**We take the accuracy of our quiz content very seriously.** If you encounter any bugs, incorrect answers, or misleading explanations, please report them by:

1. **Opening an Issue** - Create a detailed GitHub issue with:
   - The quiz name and question ID
   - The exact question text
   - Why you believe the answer is incorrect
   - Any references or documentation supporting your claim

2. **Pull Request** - If you're able to fix the issue yourself, submit a pull request with:
   - A clear description of the problem
   - Your proposed correction
   - Any references supporting the change

We aim to review and address all reports within 48 hours. Your feedback helps improve the learning experience for everyone!

## Contributing

Contributions to improve the quizzes are welcome! Here's how you can contribute:

1. **Add New Questions** - Expand the question pool with new, challenging questions
2. **Improve Explanations** - Make explanations clearer or more detailed
3. **Add New Features** - Implement new quiz features or modes
4. **Fix Bugs** - Address any issues in the code

To contribute:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request with a clear description of your improvements

## License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2023 Network Protocol Quizzes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
