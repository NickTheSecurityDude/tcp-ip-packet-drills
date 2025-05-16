#!/usr/bin/env python3
"""
TCP Flags Quiz - An interactive command-line tool for learning TCP flags and tcpdump filters.

This script provides a quiz interface for learning and testing knowledge about TCP flags,
their hex values, and how to filter them using tcpdump expressions. The quiz covers
common TCP flags (SYN, ACK, FIN, RST, PSH, URG) and their combinations.

Usage:
    python3 tcp_flags_quiz.py [-h] [-n NUM_QUESTIONS]

Arguments:
    -h, --help            Show this help message and exit
    -n NUM_QUESTIONS, --num-questions NUM_QUESTIONS
                         Number of questions to ask (default: 20)

Example:
    # Run quiz with default 20 questions
    python3 tcp_flags_quiz.py

    # Run quiz with 10 questions
    python3 tcp_flags_quiz.py -n 10

TCP Flag Values:
    FIN (0x01) - Connection termination
    SYN (0x02) - Synchronize sequence numbers
    RST (0x04) - Reset connection
    PSH (0x08) - Push buffered data
    ACK (0x10) - Acknowledgment
    URG (0x20) - Urgent pointer

The quiz tests understanding of:
- Individual TCP flag values
- Common flag combinations (e.g., SYN+ACK)
- tcpdump filter expressions
- TCP connection states
"""

import argparse
import random
import sys

class TCPFlagsQuiz:
    """
    A class that implements an interactive TCP flags quiz.

    This class provides questions about TCP flags, their hex values, and tcpdump filter
    expressions. It helps users learn about TCP flags and how to filter network traffic
    based on TCP flags using tcpdump.

    Attributes:
        num_questions (int): Number of questions to ask in the quiz (default: 20)
        score (int): Current quiz score
        questions (list): List of all available quiz questions

    Example:
        quiz = TCPFlagsQuiz(num_questions=10)
        quiz.run_quiz()
    """

    def __init__(self, num_questions=20):
        """
        Initialize the TCPFlagsQuiz with the specified number of questions.

        Args:
            num_questions (int): Number of questions to ask (default: 20)
        """
        self.num_questions = num_questions
        self.score = 0
        self.questions = [
            {
                'id': 1,
                'text': "Which flag does this match? tcpdump 'tcp[13] = 0x01'",
                'options': ["SYN", "FIN", "RST", "ACK"],
                'answer': "FIN",
                'explanation': "FIN flag (0x01) is used to close connections"
            },
            {
                'id': 2,
                'text': "True or False: tcpdump 'tcp[13] = 0x20' matches SYN packets.",
                'options': ["True", "False"],
                'answer': "False",
                'explanation': "0x20 is the URG flag, not SYN (0x02)"
            },
            {
                'id': 3,
                'text': "tcp[13] = 0x02 matches what connection phase?",
                'options': ["Connection termination", "TCP SYN (start)", "Data transfer", "Connection reset"],
                'answer': "TCP SYN (start)",
                'explanation': "SYN flag (0x02) initiates TCP connections"
            },
            {
                'id': 4,
                'text': "Fill in the missing mask: tcpdump 'tcp[tcpflags] & _____ = tcp-syn'",
                'options': ["0x01", "0x02", "0x04", "0x10"],
                'answer': "0x02",
                'explanation': "0x02 is the mask for the SYN flag"
            },
            {
                'id': 5,
                'text': "tcpdump 'tcp[13] & 0x14 = 0x14' matches what flags?",
                'options': ["SYN + ACK", "FIN + ACK", "RST + ACK", "PSH + ACK"],
                'answer': "RST + ACK",
                'explanation': "0x14 combines RST (0x04) and ACK (0x10) flags"
            },
            {
                'id': 6,
                'text': "tcp[13] = 0x04 matches which TCP flag?",
                'options': ["PSH", "ACK", "RST", "SYN"],
                'answer': "RST",
                'explanation': "RST flag (0x04) abruptly terminates connections"
            },
            {
                'id': 7,
                'text': "tcpdump 'tcp[13] & 0x01 != 0' filters what?",
                'options': ["SYN packets", "RST packets", "FIN packets", "No-flag packets"],
                'answer': "FIN packets",
                'explanation': "FIN flag (0x01) is used to close connections"
            },
            {
                'id': 8,
                'text': "tcpdump 'tcp[13] & 0x12 = 0x02' filters what?",
                'options': ["SYN-only packets", "ACK-only packets", "SYN+ACK packets", "RST packets"],
                'answer': "SYN-only packets",
                'explanation': "This checks for SYN (0x02) without ACK (0x10)"
            },
            {
                'id': 9,
                'text': "tcp[13] = 0x10 matches what?",
                'options': ["SYN packets", "ACK-only (data transfer)", "FIN packets", "RST packets"],
                'answer': "ACK-only (data transfer)",
                'explanation': "ACK flag (0x10) acknowledges received data"
            },
            {
                'id': 10,
                'text': "Which hex value matches SYN+ACK?",
                'options': ["0x02", "0x12", "0x10", "0x04"],
                'answer': "0x12",
                'explanation': "0x12 combines SYN (0x02) and ACK (0x10) flags"
            },
            {
                'id': 11,
                'text': "True or False: tcp[tcpflags] & tcp-syn != 0 matches any packet with SYN.",
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "This filter checks if the SYN bit is set, regardless of other flags"
            },
            {
                'id': 12,
                'text': "tcpdump 'tcp[13] & 0x08 != 0' matches what?",
                'options': ["Any SYN packet", "Any RST packet", "Any PSH packet", "Any ACK packet"],
                'answer': "Any PSH packet",
                'explanation': "PSH flag (0x08) tells the receiver to push data to the application"
            },
            {
                'id': 13,
                'text': "True or False: tcpdump 'tcp[13] = 0x19' matches PSH+FIN+ACK.",
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "0x19 combines PSH (0x08), FIN (0x01), and ACK (0x10) flags"
            },
            {
                'id': 14,
                'text': "Which flag combination is represented by tcp[13] = 0x11?",
                'options': ["SYN+ACK", "FIN+ACK", "RST+ACK", "PSH+ACK"],
                'answer': "FIN+ACK",
                'explanation': "0x11 combines FIN (0x01) and ACK (0x10) flags"
            },
            {
                'id': 15,
                'text': "What value completes this? tcpdump 'tcp[13] = _____' (only ACK)",
                'options': ["0x01", "0x02", "0x04", "0x10"],
                'answer': "0x10",
                'explanation': "ACK flag (0x10) acknowledges received data"
            },
            {
                'id': 16,
                'text': "tcpdump 'tcp[13] = 0x18' filters which of the following?",
                'options': ["SYN only", "PSH+ACK", "FIN+SYN", "RST only"],
                'answer': "PSH+ACK",
                'explanation': "0x18 combines PSH (0x08) and ACK (0x10) flags"
            },
            {
                'id': 17,
                'text': "True or False: tcp[13] = 0x00 matches packets with no flags set.",
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "0x00 means no flags are set in the TCP header"
            },
            {
                'id': 18,
                'text': "Which filter matches packets with either SYN or FIN flags?",
                'options': ["tcp[13] & 0x03 != 0", "tcp[13] & 0x12 != 0", "tcp[13] & 0x06 != 0", "tcp[13] & 0x11 != 0"],
                'answer': "tcp[13] & 0x03 != 0",
                'explanation': "0x03 combines SYN (0x02) and FIN (0x01) masks"
            },
            {
                'id': 19,
                'text': "Which filter excludes all ACK packets?",
                'options': ["tcp[13] & 0x10 = 0", "tcp[13] & 0x10 != 0", "tcp[13] = 0x10", "tcp[13] != 0x10"],
                'answer': "tcp[13] & 0x10 = 0",
                'explanation': "This checks that the ACK bit (0x10) is not set"
            },
            {
                'id': 20,
                'text': "Which flag does tcpdump 'tcp[tcpflags] & tcp-urg != 0' match?",
                'options': ["Only URG", "URG and any other flag", "Only RST", "RST and any other flag"],
                'answer': "URG and any other flag",
                'explanation': "tcp-urg matches the URG flag (0x20)"
            },
            {
                'id': 21,
                'text': "What does tcpdump 'tcp[13] = 0x12' filter?",
                'options': ["FIN+ACK", "SYN+ACK", "RST+ACK", "PSH+ACK"],
                'answer': "SYN+ACK",
                'explanation': "0x12 combines SYN (0x02) and ACK (0x10) flags"
            },
            {
                'id': 22,
                'text': "True or False: tcpdump 'tcp[13] & 0x03 = 0x03' matches packets with both SYN and FIN set.",
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "This checks that both SYN (0x02) and FIN (0x01) bits are set"
            },
            {
                'id': 23,
                'text': "Which flag has the hex value 0x20?",
                'options': ["SYN", "ACK", "URG", "PSH"],
                'answer': "URG",
                'explanation': "URG flag has the hex value 0x20"
            },
            {
                'id': 24,
                'text': "What does tcpdump 'tcp[13] & 0x3F = 0' filter?",
                'options': ["All TCP packets", "Packets with no common flags", "Only ECE and CWR flags", "Invalid packets"],
                'answer': "Packets with no common flags",
                'explanation': "0x3F masks the six common flags (FIN, SYN, RST, PSH, ACK, URG)"
            },
            {
                'id': 25,
                'text': "Which filter matches the third step of a TCP handshake?",
                'options': ["tcp[13] = 0x02", "tcp[13] = 0x12", "tcp[13] = 0x10", "tcp[13] = 0x04"],
                'answer': "tcp[13] = 0x10",
                'explanation': "The third step is an ACK-only packet (0x10)"
            },
            {
                'id': 26,
                'text': "What does tcpdump 'tcp[13] & 0x04 = 0x04' match?",
                'options': ["SYN-only packets", "RST-only packets", "ACK-only packets", "FIN-only packets"],
                'answer': "RST-only packets",
                'explanation': "This checks for RST (0x04) without other flags"
            },
            {
                'id': 27,
                'text': "Which filter matches packets with the PSH flag but not the ACK flag?",
                'options': ["tcp[13] = 0x08", "tcp[13] = 0x18", "tcp[13] & 0x18 = 0x08", "tcp[13] & 0x08 = 0x08"],
                'answer': "tcp[13] = 0x08",
                'explanation': "0x08 is the PSH flag without any other flags"
            },
            {
                'id': 28,
                'text': "What does tcpdump 'tcp[13] & 0x02 != 0 and tcp[13] & 0x10 = 0' filter?",
                'options': ["SYN+ACK packets", "SYN-only packets", "ACK-only packets", "RST packets"],
                'answer': "SYN-only packets",
                'explanation': "This checks for SYN (0x02) without ACK (0x10)"
            },
            {
                'id': 29,
                'text': "Which flag combination is represented by tcp[13] = 0x19?",
                'options': ["SYN+ACK+FIN", "PSH+ACK+FIN", "RST+ACK+FIN", "URG+ACK+FIN"],
                'answer': "PSH+ACK+FIN",
                'explanation': "0x19 combines PSH (0x08), ACK (0x10), and FIN (0x01) flags"
            },
            {
                'id': 30,
                'text': "True or False: tcpdump 'tcp[tcpflags] = tcp-syn|tcp-ack' is equivalent to 'tcp[13] = 0x12'.",
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "Both filter for SYN+ACK packets (0x12)"
            },
            {
                'id': 31,
                'text': "What does tcpdump 'tcp[13] & 0x10 = 0x10' match?",
                'options': ["Only ACK packets", "Any packet with ACK set", "Only SYN packets", "Any packet with SYN set"],
                'answer': "Any packet with ACK set",
                'explanation': "This checks if the ACK bit is set, regardless of other flags"
            },
            {
                'id': 32,
                'text': "Which filter matches packets with either RST or FIN flags?",
                'options': ["tcp[13] & 0x05 != 0", "tcp[13] & 0x06 != 0", "tcp[13] & 0x03 != 0", "tcp[13] & 0x14 != 0"],
                'answer': "tcp[13] & 0x05 != 0",
                'explanation': "0x05 combines RST (0x04) and FIN (0x01) masks"
            },
            {
                'id': 33,
                'text': "What does tcpdump 'tcp[13] = 0x00' filter?",
                'options': ["All TCP packets", "No TCP packets", "Packets with no flags set", "Invalid packets"],
                'answer': "Packets with no flags set",
                'explanation': "0x00 means no flags are set in the TCP header"
            },
            {
                'id': 34,
                'text': "Which flag combination is represented by tcp[13] = 0x1A?",
                'options': ["SYN+ACK+RST", "PSH+ACK+RST", "FIN+ACK+RST", "URG+ACK+RST"],
                'answer': "PSH+ACK+RST",
                'explanation': "0x1A combines PSH (0x08), ACK (0x10), and RST (0x02) flags"
            },
            {
                'id': 35,
                'text': "What does tcpdump 'tcp[13] & 0x30 = 0x30' match?",
                'options': ["ACK+SYN", "ACK+RST", "ACK+URG", "ACK+PSH"],
                'answer': "ACK+URG",
                'explanation': "0x30 combines ACK (0x10) and URG (0x20) flags"
            },
            {
                'id': 36,
                'text': "Which filter matches the second step of a TCP handshake?",
                'options': ["tcp[13] = 0x02", "tcp[13] = 0x12", "tcp[13] = 0x10", "tcp[13] = 0x04"],
                'answer': "tcp[13] = 0x12",
                'explanation': "The second step is a SYN+ACK packet (0x12)"
            },
            {
                'id': 37,
                'text': "True or False: tcpdump 'tcp[13] & 0x02 = 0x02' matches only SYN packets without other flags.",
                'options': ["True", "False"],
                'answer': "False",
                'explanation': "This matches any packet with SYN set, regardless of other flags"
            },
            {
                'id': 38,
                'text': "What does tcpdump 'tcp[13] & 0x29 = 0x29' match?",
                'options': ["FIN+PSH+URG", "FIN+ACK+URG", "SYN+ACK+URG", "RST+ACK+URG"],
                'answer': "FIN+ACK+URG",
                'explanation': "0x29 combines FIN (0x01), ACK (0x10), and URG (0x20) flags"
            },
            {
                'id': 39,
                'text': "Which filter matches packets with the ACK flag but not the SYN flag?",
                'options': ["tcp[13] & 0x12 = 0x10", "tcp[13] & 0x12 = 0x02", "tcp[13] = 0x10", "tcp[13] = 0x12"],
                'answer': "tcp[13] & 0x12 = 0x10",
                'explanation': "This checks for ACK (0x10) without SYN (0x02)"
            },
            {
                'id': 40,
                'text': "What does tcpdump 'tcp[13] & 0x17 = 0' filter?",
                'options': ["All TCP packets", "Packets with no FIN, SYN, RST, or ACK", "Only PSH packets", "Invalid packets"],
                'answer': "Packets with no FIN, SYN, RST, or ACK",
                'explanation': "0x17 masks FIN (0x01), SYN (0x02), RST (0x04), and ACK (0x10) flags"
            },
            {
                'id': 41,
                'text': "Which flag has the hex value 0x08?",
                'options': ["SYN", "ACK", "RST", "PSH"],
                'answer': "PSH",
                'explanation': "PSH flag has the hex value 0x08"
            },
            {
                'id': 42,
                'text': "What does tcpdump 'tcp[13] & 0x3F != 0' filter?",
                'options': ["All TCP packets", "Packets with at least one flag set", "Only ECE and CWR flags", "Invalid packets"],
                'answer': "Packets with at least one flag set",
                'explanation': "0x3F masks the six common flags (FIN, SYN, RST, PSH, ACK, URG)"
            },
            {
                'id': 43,
                'text': "True or False: tcpdump 'tcp[13] = 0x18' matches packets with both PSH and ACK flags set.",
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "0x18 combines PSH (0x08) and ACK (0x10) flags"
            },
            {
                'id': 44,
                'text': "Which filter matches only TCP packets where the FIN flag is set and no other flags are set?",
                'options': ["tcp[13] = 0x01", "tcp[13] = 0x11", "tcp[13] & 0x11 = 0x01", "tcp[13] & 0x01 = 0x01"],
                'answer': "tcp[13] = 0x01",
                'explanation': "0x01 is the FIN flag without any other flags"
            },
            {
                'id': 45,
                'text': "What does tcpdump 'tcp[13] & 0x07 = 0x07' match?",
                'options': ["FIN+SYN+RST", "FIN+SYN+PSH", "FIN+RST+PSH", "SYN+RST+PSH"],
                'answer': "FIN+SYN+RST",
                'explanation': "0x07 combines FIN (0x01), SYN (0x02), and RST (0x04) flags"
            },
            {
                'id': 46,
                'text': "Which filter matches packets with either PSH or URG flags?",
                'options': ["tcp[13] & 0x28 != 0", "tcp[13] & 0x18 != 0", "tcp[13] & 0x30 != 0", "tcp[13] & 0x0C != 0"],
                'answer': "tcp[13] & 0x28 != 0",
                'explanation': "0x28 combines PSH (0x08) and URG (0x20) masks"
            },
            {
                'id': 47,
                'text': "What does tcpdump 'tcp[13] = 0x04' filter?",
                'options': ["SYN-only packets", "RST-only packets", "ACK-only packets", "FIN-only packets"],
                'answer': "RST-only packets",
                'explanation': "0x04 is the RST flag without any other flags"
            },
            {
                'id': 48,
                'text': "True or False: tcpdump 'tcp[tcpflags] & tcp-fin != 0 and tcp[tcpflags] & tcp-ack != 0' matches FIN+ACK packets.",
                'options': ["True", "False"],
                'answer': "True",
                'explanation': "This checks for both FIN and ACK flags being set"
            },
            {
                'id': 49,
                'text': "Which flag combination is represented by tcp[13] = 0x14?",
                'options': ["SYN+ACK", "FIN+ACK", "RST+ACK", "PSH+ACK"],
                'answer': "RST+ACK",
                'explanation': "0x14 combines RST (0x04) and ACK (0x10) flags"
            },
            {
                'id': 50,
                'text': "What does tcpdump 'tcp[13] & 0x02 = 0x02 and tcp[13] & 0x10 = 0x10' filter?",
                'options': ["SYN-only packets", "ACK-only packets", "SYN+ACK packets", "RST packets"],
                'answer': "SYN+ACK packets",
                'explanation': "This checks for both SYN (0x02) and ACK (0x10) flags being set"
            }
        ]
    
    def run_quiz(self):
        """
        Run the TCP flags quiz.

        This method:
        1. Displays quiz introduction
        2. Randomly selects questions from the question pool
        3. Presents each question with multiple choice options
        4. Accepts and validates user answers
        5. Provides feedback and explanations
        6. Shows final score upon completion

        Users can answer with either the letter option (A, B, C, D) or the exact answer text.
        """
        print("\n===== TCP Flags Quiz =====")
        print(f"Number of questions: {self.num_questions}")
        print("===========================\n")
        
        # Shuffle questions and take the requested number
        random.shuffle(self.questions)
        quiz_questions = self.questions[:self.num_questions]
        
        for i, question in enumerate(quiz_questions):
            print(f"\nQuestion {i+1}/{self.num_questions} [ID: {question['id']}]:")
            print(question['text'])
            
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
            
            # Show explanation
            print(f"Explanation: {question.get('explanation', 'No explanation available.')}")
            
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
        - Hex values (e.g., '0x02' matches '0x02')
        - TCP flag combinations (e.g., 'SYN+ACK' matches 'ACK+SYN')

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
        
        # Handle flag combinations
        flag_patterns = {
            'fin': ['fin', '0x01', 'tcp-fin'],
            'syn': ['syn', '0x02', 'tcp-syn'],
            'rst': ['rst', '0x04', 'tcp-rst'],
            'psh': ['psh', '0x08', 'tcp-psh'],
            'ack': ['ack', '0x10', 'tcp-ack'],
            'urg': ['urg', '0x20', 'tcp-urg'],
            'fin+ack': ['fin+ack', 'ack+fin', '0x11', 'tcp-fin|tcp-ack'],
            'syn+ack': ['syn+ack', 'ack+syn', '0x12', 'tcp-syn|tcp-ack'],
            'rst+ack': ['rst+ack', 'ack+rst', '0x14', 'tcp-rst|tcp-ack'],
            'psh+ack': ['psh+ack', 'ack+psh', '0x18', 'tcp-psh|tcp-ack']
        }
        
        for key, patterns in flag_patterns.items():
            if correct_answer in patterns and user_answer in patterns:
                return True
        
        return False

def main():
    """
    Main entry point for the TCP Flags Quiz.

    This function:
    1. Sets up command-line argument parsing
    2. Creates a TCPFlagsQuiz instance with user-specified options
    3. Runs the quiz
    4. Handles keyboard interrupts gracefully
    """
    parser = argparse.ArgumentParser(description='TCP Flags Quiz')
    parser.add_argument('-n', '--num-questions', type=int, default=20,
                        help='Number of questions (default: 20)')
    
    args = parser.parse_args()
    
    quiz = TCPFlagsQuiz(num_questions=args.num_questions)
    quiz.run_quiz()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nQuiz terminated by user.")
        sys.exit(0)