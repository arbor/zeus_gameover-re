# ZeusGameover.py
#
# Dennis Schwarz, Arbor Networks ASERT, February 2013

import sys
import pefile
import re
import struct
import random
import socket
import md5
import zlib


class ZeusGameoverError(Exception):
    pass


class ZeusGameover:
    """
    post process zeus gameover memdumps:

    - extract static peers
    - query static peers for config
    - enumerate p2p network
    """
    # number of static peers in memdump
    NUM_PEER_ENTRIES = 20

    # length of peer entry
    PEER_ENTRY_LEN = 45

    # senderID and incoming rc4 key
    SENDER_ID = "c9a370355e879b521171b90d22ea4f15f7b1b556".decode("hex")

    # max response packet size
    MAX_PACKET_SIZE = 4096

    # socket timeout
    SOCK_TIMEOUT = 2

    # additional new peers threshold, percent
    NEW_PEER_THRES = 0.50


    def __init__(self, memdump):
        self.pe = self.get_pe(memdump)
        self.memdump_data = self.pe.get_memory_mapped_image()
        self.memdump_config = self.get_memdump_config()
        self.memdump_rc4_key = self.get_memdump_rc4_key()
        self.static_peers = self.get_static_peers()
        self.peers = self.enumerate_peers()


    def get_pe(self, memdump):
        """
        parse memdump into PE file format
        """
        pe = None

        try:
            pe = pefile.PE(data=memdump)
        except pefile.PEFormatError as err:
            raise ZeusGameoverError("get_pe: %s" % err)

        return pe


    def get_memdump_config(self):
        """
        find and decrypt memdump config
        """
        # find function based on opcodes

        # AML-11294187.rsrc-38979806.dynamic.memdump 0x424BA2
        # push  esi
        # push  edi
        # mov   edi, 56Ch
        # push  edi
        # mov   esi, ecx
        # push offset stru_406FC8
        match = re.search("\x56\x57\xbf.{2}\x00\x00\x57\x8b\xf1\x68", self.memdump_data)
        if not match:
            raise ZeusGameoverError("get_memdump_config: config not found - no function match")

        func_offset = match.start()

        # extract config
        config_len = self.pe.get_dword_from_offset(func_offset+0x3)
        config_addr = self.pe.get_dword_from_offset(func_offset+0xb)
        config_offset = config_addr - self.pe.OPTIONAL_HEADER.ImageBase
        config = self.memdump_data[config_offset:config_offset+config_len]
        if not config:
            raise ZeusGameoverError("get_memdump_config: config not found - no data @ 0x%x" % config_addr)

        # extract key
        xor_key = self.get_memdump_config_xor_key(config_len)

        # decrypt config
        plain = []
        for offset, enc_byte in enumerate(config):
            key_byte = xor_key[offset]
            plain_byte = ord(enc_byte) ^ ord(key_byte)
            plain.append(chr(plain_byte))

        return plain


    def get_memdump_config_xor_key(self, config_len):
        """
        get xor key for memdump config
        """
        key = []

        for section in self.pe.sections:
            if section.Name.startswith(".reloc"):
                key = self.memdump_data[section.VirtualAddress:section.VirtualAddress+config_len]
                break

        return key


    def get_memdump_rc4_key(self):
        """
        extract rc4 key from memdump config
        """
        rc4_key_offset = self.get_rc4_key_offset()
        if not rc4_key_offset:
            raise ZeusGameoverError("get_memdump_rc4_key: unknown rc4 offset")

        key = self.memdump_config[rc4_key_offset:rc4_key_offset+258]

        return key


    def get_rc4_key_offset(self):
        """ 
        extract rc4 key offset from memdump
        """
        # @TODO opcodes need further validation

        # AML-11294187.rsrc-38979806.dynamic.memdump 0x40fbe6
        # lea   ecx, [esp+1Ch]
        # call  sub_blah
        # lea   eax, [esp+454h]
        # push

        # @TODO if we get too many, it would be worth integrating an asm module and matching on instructions
        # opcode case #1
        code_offset = re.search(r"\x8d\x4c\x24(.{1})\xe8.{4}\x8d\x84\x24(.{4})\x6a", self.memdump_data)
        # opcode case #2
        code_offset2 = re.search(r"\x8d\x4c\x24(.{1})\xe8.{4}\x8d\x44\x24(.{1})\x6a", self.memdump_data)

        if code_offset:
            x = struct.unpack("B", code_offset.groups()[0])[0]
            y = struct.unpack("I", code_offset.groups()[1])[0]
        elif code_offset2:
            x = struct.unpack("B", code_offset2.groups()[0])[0]
            y = struct.unpack("B", code_offset2.groups()[1])[0]
        else:
            raise ZeusGameoverError("get_rc4_key_offset: rc4 key not found")

        offset = y-x
        return offset


    def get_static_peers(self):
        """
        extract static peers from memdump and query for version and config
        """
        peer_array_offset = self.get_peer_array_offset()
        if not peer_array_offset:
            raise ZeusGameoverError("get_static_peers: unknown peer array offset")
        
        peers = []
        for i in range(self.NUM_PEER_ENTRIES):
            offset = i*self.PEER_ENTRY_LEN+peer_array_offset
            peer = self.get_peer(self.memdump_config, offset)
            peers.append(peer)

        return peers


    def get_peer_array_offset(self):
        """
        extract peer array offset from memdump
        """
        # @TODO opcodes need further validation

        # AML-11294187.rsrc-38979806.dynamic.memdump 0x413906
        # lea   ecx, [esp+88h]
        # call  sub_blah
        # push  14h
        # lea   edi, [esp+11bh]

        code_offset = re.search(r"\x8d\x8c\x24(.{4})\xe8.{4}\x6a.{1}\x8d\xbc\x24(.{4})", self.memdump_data)

        x = struct.unpack("I", code_offset.groups()[0])[0]
        y = struct.unpack("I", code_offset.groups()[1])[0]

        offset = y-x-4
        return offset


    def get_peer(self, data, offset, quick=False):
        """
        extract a peer from a chunk of data
        """
        peer = {}

        peer_entry = data[offset:offset+self.PEER_ENTRY_LEN]

        key = "".join(peer_entry[0x1:0x1+0x14])
        peer["key"] = key

        ip = ".".join(["%s" % ord(byte) for byte in peer_entry[0x15:0x15+0x4]])
        peer["ip"] = ip

        port = struct.unpack("H", "".join(peer_entry[0x19:0x19+0x2]))[0]
        peer["port"] = port

        if not quick:
            peer = self.query_peer_for_version(peer)

            if "tcp_port" in peer and self.memdump_rc4_key:
                peer = self.query_peer_for_config(peer)

        return peer


    def query_peer_for_version(self, peer):
        """
        query peer for its version info, 0x00 command
        """
        p2p_header, junk_size = self.get_p2p_header(0x00)

        # 0x00 cmd
        data = ""

        junk = self.get_junk(junk_size)

        command = p2p_header + data + junk

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.SOCK_TIMEOUT)

        encrypted_command = self.rc4(peer["key"], command)

        response = None
        try:
            sock.sendto(encrypted_command, (peer["ip"], peer["port"]))
            response = sock.recv(self.MAX_PACKET_SIZE)
        except:
            pass

        sock.close()

        if response:
            decrypted_response = self.rc4(self.SENDER_ID, response)
            peer = self.parse_version_response(peer, decrypted_response)

        return peer


    def query_peer_for_config(self, peer):
        """ 
        query peer for its config, 0x68 command
        """
        p2p_header, junk_size = self.get_p2p_header(0x68)

        # 0x68 cmd
        data = ""

        junk = self.get_junk(junk_size)

        command = p2p_header + data + junk

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.SOCK_TIMEOUT)

        encrypted_command = self.rc4(peer["key"], command)

        response = ""
        try:
            sock.connect((peer["ip"], peer["tcp_port"]))
            sock.send(encrypted_command)

            while 1:
                segment = sock.recv(self.MAX_PACKET_SIZE)
                if not segment:
                    break
                response += segment
        except:
            pass

        sock.close()

        if response:
            decrypted_response = self.rc4(self.SENDER_ID, response)
            peer = self.parse_config_response(peer, decrypted_response)

        return peer


    def get_p2p_header(self, cmd):
        """
        generate a P2P header
        """
        #rand_byte = random.randint(1, 255)      # 1 byte, random value, not 0
        rand_byte = 0x44                         # @TODO rand_byte, ttl, and ssid are related somehow, use hardcoded for now
        header = struct.pack("B", rand_byte)

        #ttl = random.randint(0, 255)            # 1 byte, TTL field or random value (when not used)
        ttl = 0x73                               # @TODO rand_byte, ttl, and ssid are related somehow, use hardcoded for now
        header += struct.pack("B", ttl)

        junk_size = random.randint(0, 255)      # 1 byte, number of extra bytes to append to end of packet
        header += struct.pack("B", junk_size)

        header += struct.pack("B", cmd)        # 1 byte, cmd

        #for i in range(20):                     # SSID, 20 bytes
        #    ssid_byte = random.randint(0, 255)
        #    header += struct.pack("B", ssid_byte)
        header += "\xbb\x8c\x79\xa8\x5a\xf1\xe1\x94\xe0\x19\xae\x72\x56\x68\xfc\x1b\x42\xf7\xda\x3a"    # @TODO rand_byte, ttl, and ssid are related somehow, use hardcoded for now

        header += self.SENDER_ID     # senderID, 20 bytes

        return header, junk_size


    def get_junk(self, junk_size):
        """
        get junk bytes
        """
        junk = ""
        for i in range(junk_size):      # junk_size junk bytes
            junk_byte = random.randint(0, 255)
            junk += struct.pack("B", junk_byte)

        return junk


    def rc4(self, key, in_buf):
        """
        rc4 encrypt/decrypt
        """
        out_buf = []
        i = 0
        j = 0
        S = self.ksa(key)

        for byte in in_buf:
            (i, j, S, K) = self.prga(i, j, S)
            new_byte = ord(byte) ^ K
            out_buf.append(chr(new_byte))

        return "".join(out_buf)


    def rc4_keystate(self, key_state, in_buf):
        """ 
        rc4 decrypted with exisiting KSA
        """
        out_buf = []
        i = ord(key_state[256])
        j = ord(key_state[257])
        S = [ord(byte) for byte in key_state[:256]]

        for byte in in_buf:
            (i, j, S, K) = self.prga(i, j, S)
            new_byte = ord(byte) ^ K 
            out_buf.append(chr(new_byte))

        return "".join(out_buf)


    # the key-scheduling algorithm (KSA)
    def ksa(self, key):
        S = []
        # init to identity permutation
        for i in range(256):
            S.append(i)

        j = 0 
        for i in range(256):
            # equal: j = (j + S[i] + ord(key[i % len(key)])) & 255
            j = (j + S[i] + ord(key[i % len(key)])) % 256 
            S = self.swap(S, i, j)

        return S


    # swap list elements
    def swap(self, S, i, j): 
        S[i], S[j] = S[j], S[i]

        return S


    # the pseudo-random generation algorithm (PRGA)
    def prga(self, i, j, S):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S = self.swap(S, i, j)
        K = S[(S[i] + S[j]) % 256]

        return (i, j, S, K)


    def parse_version_response(self, peer, response):
        """
        parse version response
        """
        # sanity check, make sure response command is 0x1
        if ord(response[0x3]) != 0x1:
            raise ZeusGameoverError("parse_version_response: bad response command: %x" % ord(response[0x3]))

        data = self.strip_response(response)

        peer["binary_ver"] = struct.unpack("I", "".join(data[0:4]))[0]
        peer["config_ver"] = struct.unpack("I", "".join(data[4:8]))[0]
        peer["tcp_port"] = struct.unpack("H", "".join(data[8:10]))[0]

        return peer


    def parse_config_response(self, peer, response):
        """
        parse config response
        """
        length = struct.unpack("I", "".join(response[0:4]))[0]
        rc4_decrypted_response = self.rc4_keystate(self.memdump_rc4_key, response[4:])
        plain = self.dexor(rc4_decrypted_response)

        # sanity checks
        # total length
        if length != len(plain):
            raise ZeusGameoverError("parse_config_response: bad total length")

        # config length -- subtract trailing rsa key at end
        calculated_len_of_conf = len(plain)-256
        len_of_conf = struct.unpack("I", "".join(plain[20:24]))[0]
        if calculated_len_of_conf != len_of_conf:
            raise ZeusGameoverError("parse_config_response: bad config length")

        # md5 check
        calculated_hash_of_conf = "%04x%04x%04x%04x" % struct.unpack(">IIII", md5.new("".join(plain[48:len(plain)-256])).digest())
        hash_of_conf = "%04x%04x%04x%04x" % struct.unpack(">IIII", "".join(plain[32:32+16]))
        if calculated_hash_of_conf != hash_of_conf:
            raise ZeusGameoverError("parse_config_response: bad md5 check")

        # @TODO complete config parser
        # parse config
        peer["config"] = self.parse_config(plain)
        peer["config_len"] = len_of_conf

        return peer


    def parse_config(self, plain):
        """
        parse zeus gameover config

        @TODO complete config parser
        """
        config_version = struct.unpack("I", "".join(plain[28:32]))[0]

        # chop off StorageHeader and trailing rsa key
        items_blob = plain[48:-256]
        items_blob_len = len(items_blob)
        current_position = 0
        config = ""

        while current_position < items_blob_len:
            # get config entry pieces
            item_number = struct.unpack("I", "".join(items_blob[current_position:current_position+4]))[0]
            item_type = struct.unpack("I", "".join(items_blob[current_position+4:current_position+8]))[0]
            item_size_packed = struct.unpack("I", "".join(items_blob[current_position+8:current_position+12]))[0]
            item_size_unpacked = struct.unpack("I", "".join(items_blob[current_position+12:current_position+16]))[0]
            item_data = "".join(items_blob[current_position+16:current_position+16+item_size_packed])

            # decrypt data
            xor_key = (item_size_packed << 0x10) | (item_number & 0xFFFF) | (config_version << 8) & 0xffffffff
            xor_key_str = struct.pack("I", xor_key)
            data = []
            for i in range(len(item_data)):
                plain_byte = ord(item_data[i]) ^ ord(xor_key_str[i % 4])
                data.append(chr(plain_byte))

            # decompress if necessary
            if item_type & 0x1 == 1:
                data = zlib.decompress("".join(data), -15)

            # format entry
            config += "[start item number: %d, type: 0x%x, packed size: %d, unpacked size: %d]\n" % \
                (item_number, item_type, item_size_packed, item_size_unpacked)
            config += "".join(data)
            config += "\n"
            config += "[end item number: %d]\n" % item_number

            current_position += 16 + item_size_packed

        return config


    def dexor(self, message):
        """
        dexor message, aka visual decrypt in zeus-talk
        """
        plain = []

        for i in range(len(message)-1, 0, -1):
            plain_byte = ord(message[i]) ^ ord(message[i-1])
            plain.append(chr(plain_byte))

        plain.append(message[0])
        plain.reverse()

        return plain


    def strip_response(self, response):
        """
        strip off p2p header and trailing junk bytes
        """
        junk_size = ord(response[0x2])
        data = response[0x2c:-junk_size]

        return data


    def get_static_peers_list(self):
        """
        return the list of static peers
        """
        return self.static_peers


    def get_peers_list(self):
        """
        return the list of peers
        """
        return self.peers


    def enumerate_peers(self):
        """
        enumerate p2p network, breadth first traversal
        """
        all_peers = []
        old_peers = []
        last_len = 0

        # init with static peers
        for peer in self.static_peers:
            all_peers.append(peer)
            old_peers.append(peer)

        while old_peers:
            # break if we're adding new peers too slowly
            percent = (len(all_peers) - last_len) / (len(all_peers) * 1.0)
            if percent < self.NEW_PEER_THRES:
                break
            last_len = len(all_peers)

            new_peers = []
            for old_peer in old_peers:
                peers = self.query_peer_for_peers(old_peer)

                if peers:
                    for peer in peers:
                        if peer not in all_peers:
                            all_peers.append(peer)
                            new_peers.append(peer)

            old_peers = new_peers

        return all_peers


    def query_peer_for_peers(self, peer):
        """ 
        query peer for its peers, 0x02 command
        """
        p2p_header, junk_size = self.get_p2p_header(0x02)

        # 0x02 cmd
        data = peer["key"]      # reqID, 20 bytes

        for i in range(8):      # randomFill, 8 bytes
            random_fill = random.randint(1, 255)        # non-zero random bytes
            data += struct.pack("B", random_fill)

        junk = self.get_junk(junk_size)

        command = p2p_header + data + junk

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.SOCK_TIMEOUT)

        encrypted_command = self.rc4(peer["key"], command)

        response = ""
        try:
            sock.sendto(encrypted_command, (peer["ip"], peer["port"]))
            response = sock.recv(self.MAX_PACKET_SIZE)
        except:
            pass

        sock.close()

        peers = []
        if response:
            decrypted_response = self.rc4(self.SENDER_ID, response)
            peers = self.parse_peers_response(decrypted_response)

        return peers


    def parse_peers_response(self, response):
        """
        parse peers response
        """
        peers = []
        # sanity check, make sure response command is 0x3
        if ord(response[0x3]) != 0x3:
            raise ZeusGameoverError("parse_peers_response: bad response command: %x" % ord(response[0x3]))

        data = self.strip_response(response)
        
        for i in range(len(data)/self.PEER_ENTRY_LEN):
            offset = i*self.PEER_ENTRY_LEN
            peer = self.get_peer(data, offset, quick=True)
            peers.append(peer)

        return peers


    def format_peer_entry(self, peer):
        """ 
        pretty format a peer entry
        """
        entry = []

        entry += ["    ip: %s, udp port: %d, rc4 key: %s" % \
            (peer["ip"], peer["port"], "".join(peer["key"]).encode('hex'))]

        if "binary_ver" in peer:
            entry += ["    binary version: %d, config version: %d, tcp port: %d" % \
                (peer["binary_ver"], peer["config_ver"], peer["tcp_port"])]

        if "config" in peer:
            entry += ["    config saved (%d actual bytes)" % peer["config_len"]]

        entry += [""]

        return entry


if __name__ == "__main__":

    fp = open(sys.argv[1], "rb")
    memdump = fp.read()
    fp.close()

    try:
        zeus_gameover = ZeusGameover(memdump)
    except ZeusGameoverError as msg:
        print "Error: %s" % msg
        sys.exit(1)

    static_peers = zeus_gameover.get_static_peers_list()
    formatted = []
    for i, peer in enumerate(static_peers):
        formatted += ["static peer #%d" % (i+1)]
        formatted += zeus_gameover.format_peer_entry(peer)
    print "\n".join(formatted)

    # save configs
    for peer in static_peers:
        if "config" in peer:
            filename = "%s.config" % peer["ip"]
            fp = open(filename, "wb")
            fp.write(peer["config"])
            fp.close()

    peers = zeus_gameover.get_peers_list()
    formatted = []
    for i, peer in enumerate(peers):
        formatted += ["peer #%d" % (i+1)]
        formatted += zeus_gameover.format_peer_entry(peer)
    print "\n".join(formatted)
