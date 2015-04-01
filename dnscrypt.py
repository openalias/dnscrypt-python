# Copyright (c) 2014-2015, The Monero Project
# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import struct
import StringIO
import time
import datetime
import os
from slownacl import poly1305, xsalsa20poly1305

USE_LOCAL_LIBS = 1

# OCTET 1,2     ID
# OCTET 3,4 QR(1 bit) + OPCODE(4 bit)+ AA(1 bit) + TC(1 bit) + RD(1 bit)+ RA(1 bit) +
#       Z(3 bit) + RCODE(4 bit)
# OCTET 5,6 QDCOUNT
# OCTET 7,8 ANCOUNT
# OCTET 9,10    NSCOUNT
# OCTET 11,12   ARCOUNT


class DnsHeader:
    def __init__(self):
        self.id = 0x1234
        self.bits = 0x0100  # recursion desired
        self.qdCount = 0
        self.anCount = 0
        self.nsCount = 0
        self.arCount = 1

    def toBinary(self):
        return struct.pack('!HHHHHH',
            self.id,
            self.bits,
            self.qdCount,
            self.anCount,
            self.nsCount,
            self.arCount)

    def fromBinary(self, bin):
        if bin.read:
            bin = bin.read(12)
        (self.id,
         self.bits,
         self.qdCount,
         self.anCount,
         self.nsCount,
         self.arCount) = struct.unpack('!HHHHHH', bin)
        return self

    def __repr__(self):
        return '<DnsHeader %d, %d questions, %d answers>' % (self.id, self.qdCount, self.anCount)


class DnsResourceRecord:
    pass


class DnsAnswer(DnsResourceRecord):
    pass


class DnsQuestion:
    def __init__(self):
        self.labels = []
        self.qtype = 1  # A-record
        self.qclass = 1  # the Internet

    def toBinary(self):
        bin = ''
        for label in self.labels:
            assert len(label) <= 63
            bin += struct.pack('B', len(label))
            bin += label
        bin += '\0'  # Labels terminator
        bin += struct.pack('!HH', self.qtype, self.qclass)
        return bin


class DnsPacket:
    def __init__(self, header=None):
        self.header = header
        self.questions = []
        self.answers = []

    def addQuestion(self, question):
        self.header.qdCount += 1
        self.questions.append(question)

    def toBinary(self):
        bin = self.header.toBinary()
        for question in self.questions:
            bin += question.toBinary()
        return bin

    def __repr__(self):
        return '<DnsPacket %s>' % (self.header)


class DnscryptException(Exception):
    pass


class BinReader(StringIO.StringIO):
    def unpack(self, fmt):
        size = struct.calcsize(fmt)
        bin = self.read(size)
        return struct.unpack(fmt, bin)


class DnsPacketConverter:
    def fromBinary(self, bin):
        reader = BinReader(bin)
        header = DnsHeader().fromBinary(reader)
        packet = DnsPacket(header)
        for qi in range(header.qdCount):
            q = self.readQuestion(reader)
            packet.questions.append(q)
        for ai in range(header.anCount):
            aa = self.readAnswer(reader)
            packet.answers.append(aa)
        return packet

    def readQuestion(self, reader):
        question = DnsQuestion()
        question.labels = self.readLabels(reader)
        (question.qtype, question.qclass) = reader.unpack('!HH')
        return question

    def readAnswer(self, reader):
        answer = DnsAnswer()
        answer.name = self.readLabels(reader)
        (type, rrclass, ttl, rdlength) = reader.unpack('!HHiH')
        answer.rdata = reader.read(rdlength)
        return answer.rdata

    def readLabels(self, reader):
        labels = []
        while True:
            (length,) = reader.unpack('B')
            if length == 0:
                break

            # Compression
            compressionMask = 0b11000000
            if length & compressionMask:
                byte1 = length & ~compressionMask
                (byte2,) = reader.unpack('B')
                offset = byte1 << 8 | byte2
                oldPosition = reader.tell()
                result = self.readLabels(reader)
                reader.seek(oldPosition)
                return result

            label = reader.read(length)
            labels.append(label)
        return labels


def get_public_key(ip, port, provider_key, provider_url):
    '''Get public key from provider.'''
    header = DnsHeader()

    question = DnsQuestion()
    question.labels = provider_url.split('.')
    question.qtype = 16  # TXT record

    packet = DnsPacket(header)
    packet.addQuestion(question)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dest = (ip, port)
    sock.sendto(packet.toBinary(), dest)

    (response, address) = sock.recvfrom(1024)

    bincert = response.encode('hex')[-232:]

    cert_start = datetime.datetime.fromtimestamp(int(bincert[216:224], 16))
    cert_end = datetime.datetime.fromtimestamp(int(bincert[224:], 16))
    now = datetime.datetime.now()

    if now < cert_start or now > cert_end:
        raise DnscryptException("Certificate expired.")

    if USE_LOCAL_LIBS:
        try:
            import pysodium
            return pysodium.crypto_sign_open(bincert.decode('hex'), provider_key.decode('hex'))
        except ImportError:
            pass

        try:
            import nacl
            import nacl.bindings
            return nacl.bindings.crypto_sign_open(bincert.decode('hex'), provider_key.decode('hex'))
        except ImportError:
            pass

    import ed25519py
    return ed25519py.crypto_sign_open(bincert.decode('hex'), provider_key.decode('hex'))


def generate_keypair():
    if USE_LOCAL_LIBS:
        try:
            import nacl
            import nacl.bindings
            return nacl.bindings.crypto_box_keypair()
        except ImportError:
            pass
    return xsalsa20poly1305.box_curve25519xsalsa20poly1305_keypair()


def create_nmkey(pk, sk):
    try:
        if USE_LOCAL_LIBS:
            try:
                import nacl
                import nacl.bindings
                return nacl.bindings.crypto_box_beforenm(pk, sk)
            except ImportError:
                pass
        return xsalsa20poly1305.box_curve25519xsalsa20poly1305_beforenm(pk, sk)
    except ValueError:
        raise DnscryptException("Invalid public key.")


def encode_message(message, nonce, nmkey):
    try:
        if USE_LOCAL_LIBS:
            try:
                import nacl
                import nacl.bindings
                return nacl.bindings.crypto_box_afternm(message, nonce + 12 * '\x00', nmkey)
            except ImportError:
                pass
        return xsalsa20poly1305.box_curve25519xsalsa20poly1305_afternm(message, nonce + 12 * '\x00', nmkey)
    except ValueError:
        raise DnscryptException("Message encoding error.")


def decode_message(answer, nonce, nmkey):
    try:
        if USE_LOCAL_LIBS:
            try:
                import nacl
                import nacl.bindings
                return nacl.bindings.crypto_box_open_afternm(answer, nonce, nmkey)
            except ImportError:
                pass
        return xsalsa20poly1305.box_curve25519xsalsa20poly1305_open_afternm(answer, nonce, nmkey)
    except ValueError:
        raise DnscryptException("Message decoding error.")


def query(url, ip, port, provider_key, provider_url, record_type=1):
    # get public key from provider
    try:
        provider_pk = get_public_key(ip, port, provider_key, provider_url)[:32]
    except DnscryptException:
        raise DnscryptException("Certificate expired.")

    magic_query = '7PYqwfzt'

    # create dns query
    header = DnsHeader()

    question = DnsQuestion()
    question.labels = url.split('.')
    question.qtype = record_type

    packet = DnsPacket(header)
    packet.addQuestion(question)

    # generate a local keypair
    (pk, sk) = generate_keypair()

    # create nmkey out of provider's public key and local secret key
    nmkey = create_nmkey(provider_pk, sk)

    message = packet.toBinary() + '\x00\x00\x29\x04\xe4' + 6 * '\x00' + '\x80' + 404 * '\x00'

    nonce = "%x" % int(time.time()) + os.urandom(4)

    encoded_message = encode_message(message, nonce, nmkey)

    #poly = poly1305.onetimeauth_poly1305(encoded_message, provider_pk)  not quite sure if that's needed for something...

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dest = (ip, port)

    sock.sendto(magic_query + pk + nonce + encoded_message, dest)
    (response, address) = sock.recvfrom(1024)

    resp_magic_query = response[:8]
    resp_client_nonce = response[8:20]
    resp_server_nonce = response[20:32]
    resp_answer = response[32:]

    if resp_magic_query != 'r6fnvWj8':
        raise DnscryptException("Invalid magic query received.")
    if resp_client_nonce != nonce:
        raise DnscryptException("Invalid nonce received.")

    decoded_answer = decode_message(resp_answer, resp_client_nonce + resp_server_nonce, nmkey)

    conv = DnsPacketConverter()
    packet = conv.fromBinary(decoded_answer)
    return packet

