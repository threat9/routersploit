# MIT License
# The code is taken from https://github.com/LaiArturs/RouterOS_API/
# All credits go to Arturs Laizans - https://github.com/LaiArtur

import sys
import binascii
import hashlib
import socket
import ssl

 
TIMEOUT = 8.0
 
CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE
CONTEXT.set_ciphers("ADH:ALL")


class LoginError(Exception):
    pass


class WordTooLong(Exception):
    pass


class CreateSocketError(Exception):
    pass


class RouterOSTrapError(Exception):
    pass


class ApiRosClient(object):
    "RouterOS API"

    def __init__(self, address, port, user, password, use_ssl=False,
                 context=CONTEXT, timeout=TIMEOUT):

        self.address = address
        self.user = user
        self.password = password
        self.use_ssl = use_ssl
        self.port = port
        self.context = context
        self.timeout = timeout

        # Port setting logic
        if port:
            self.port = port
        elif use_ssl:
            self.port = SSL_PORT
        else:
            self.port = PORT

        self.sock = None
        self.connection = None

    # Open socket connection with router and wrap with SSL if needed.
    def open_socket(self):

        for res in socket.getaddrinfo(self.address, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res

        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)

        try:
            # Trying to connect to RouterOS, error can occur if IP address is not reachable, or API is blocked in
            # RouterOS firewall or ip services, or port is wrong.
            self.connection = self.sock.connect(sa)

        except OSError:
            raise CreateSocketError('Error: API failed to connect to socket. Host: {}, port: {}.'.format(self.address,
                                                                                                         self.port))

        if self.use_ssl:
            self.sock = self.context.wrap_socket(self.sock)

    def login(self):

        def reply_has_error(reply):
            # Check if reply contains login error
            if len(reply[0]) == 2 and reply[0][0] == '!trap':
                return True
            else:
                return False

        def process_old_login(reply):
            # RouterOS uses old API login method, code continues with old method
            md5 = hashlib.md5(('\x00' + self.password).encode('utf-8'))
            md5.update(binascii.unhexlify(reply[0][1][5:]))
            sentence = ['/login', '=name=' + self.user, '=response=00'
                        + binascii.hexlify(md5.digest()).decode('utf-8')]
            reply = self.communicate(sentence)
            return check_reply(reply)

        def check_reply(reply):
            if len(reply[0]) == 1 and reply[0][0] == '!done':
                # If login process was successful
                return reply
            elif reply_has_error(reply):
                raise LoginError(reply)
            elif len(reply[0]) == 2 and reply[0][1][0:5] == '=ret=':
                return process_old_login(reply)
            else:
                raise LoginError(f'Unexpected reply to login: {reply}')

        sentence = ['/login', '=name=' + self.user, '=password=' + self.password]
        reply = self.communicate(sentence)
        return check_reply(reply)

    # Sending data to router and expecting something back
    def communicate(self, sentence_to_send):

        # There is specific way of sending word length in RouterOS API.
        # See RouterOS API Wiki for more info.
        def send_length(w):
            length_to_send = len(w)
            if length_to_send < 0x80:
                num_of_bytes = 1  # For words smaller than 128
            elif length_to_send < 0x4000:
                length_to_send += 0x8000
                num_of_bytes = 2  # For words smaller than 16384
            elif length_to_send < 0x200000:
                length_to_send += 0xC00000
                num_of_bytes = 3  # For words smaller than 2097152
            elif length_to_send < 0x10000000:
                length_to_send += 0xE0000000
                num_of_bytes = 4  # For words smaller than 268435456
            elif length_to_send < 0x100000000:
                num_of_bytes = 4  # For words smaller than 4294967296
                self.sock.sendall(b'\xF0')
            else:
                raise WordTooLong('Word is too long. Max length of word is 4294967295.')
            self.sock.sendall(length_to_send.to_bytes(num_of_bytes, byteorder='big'))

            # Actually I haven't successfully sent words larger than approx. 65520.
            # Probably it is some RouterOS limitation of 2^16.

        # The same logic applies for receiving word length from RouterOS side.
        # See RouterOS API Wiki for more info.
        def receive_length():
            r = self.sock.recv(1)  # Receive the first byte of word length

            # If the first byte of word is smaller than 80 (base 16),
            # then we already received the whole length and can return it.
            # Otherwise if it is larger, then word size is encoded in multiple bytes and we must receive them all to
            # get the whole word size.

            if r < b'\x80':
                r = int.from_bytes(r, byteorder='big')
            elif r < b'\xc0':
                r += self.sock.recv(1)
                r = int.from_bytes(r, byteorder='big')
                r -= 0x8000
            elif r < b'\xe0':
                r += self.sock.recv(2)
                r = int.from_bytes(r, byteorder='big')
                r -= 0xC00000
            elif r < b'\xf0':
                r += self.sock.recv(3)
                r = int.from_bytes(r, byteorder='big')
                r -= 0xE0000000
            elif r == b'\xf0':
                r = self.sock.recv(4)
                r = int.from_bytes(r, byteorder='big')

            return r

        def read_sentence():
            rcv_sentence = []  # Words will be appended here
            rcv_length = receive_length()  # Get the size of the word

            while rcv_length != 0:
                received = b''
                while rcv_length > len(received):
                    rec = self.sock.recv(rcv_length - len(received))
                    if rec == b'':
                        raise RuntimeError('socket connection broken')
                    received += rec
                received = received.decode('utf-8', 'backslashreplace')
                rcv_sentence.append(received)
                rcv_length = receive_length()  # Get the size of the next word
            return rcv_sentence

        # Sending part of conversation

        # Each word must be sent separately.
        # First, length of the word must be sent,
        # Then, the word itself.
        for word in sentence_to_send:
            send_length(word)
            self.sock.sendall(word.encode('utf-8'))  # Sending the word
        self.sock.sendall(b'\x00')  # Send zero length word to mark end of the sentence

        # Receiving part of the conversation

        # Will continue receiving until receives '!done' or some kind of error (!trap).
        # Everything will be appended to paragraph variable, and then returned.
        paragraph = []
        received_sentence = ['']
        while received_sentence[0] != '!done':
            received_sentence = read_sentence()
            paragraph.append(received_sentence)
        return paragraph

    # Initiate a conversation with the router
    def talk(self, message):

        # It is possible for message to be string, tuple or list containing multiple strings or tuples
        if type(message) == str or type(message) == tuple:
            return self.send(message)
        elif type(message) == list:
            reply = []
            for sentence in message:
                reply.append(self.send(sentence))
            return reply
        else:
            raise TypeError('talk() argument must be str or tuple containing str or list containing str or tuples')

    def send(self, sentence):
        # If sentence is string, not tuples of strings, it must be divided in words
        if type(sentence) == str:
            sentence = sentence.split()
        reply = self.communicate(sentence)

        # If RouterOS returns error from command that was sent
        if '!trap' in reply[0][0]:
            # You can comment following line out if you don't want to raise an error in case of !trap
            raise RouterOSTrapError("\nCommand: {}\nReturned an error: {}".format(sentence, reply))
            pass

        # reply is list containing strings with RAW output form API
        # nice_reply is a list containing output form API sorted in dictionary for easier use later
        nice_reply = []
        for m in range(len(reply) - 1):
            nice_reply.append({})
            for k, v in (x[1:].split('=', 1) for x in reply[m][1:]):
                nice_reply[m][k] = v
        return nice_reply

    def is_alive(self) -> bool:
        """Check if socket is alive and router responds"""

        # Check if socket is open in this end
        try:
            self.sock.settimeout(2)
        except OSError:
            return False

        # Check if we can send and receive through socket
        try:
            self.talk('/system/identity/print')

        except (socket.timeout, IndexError, BrokenPipeError):
            self.close()
            return False

        self.sock.settimeout(self.timeout)
        return True

    def create_connection(self):
        self.open_socket()
        self.login()

    def close(self):
        self.sock.close()

