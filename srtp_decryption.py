import Crypto.Cipher.AES as AES
import Crypto.Util.Counter as AESCounter

from struct import pack,unpack
from bitstring import BitArray #pip install bitstring
from functools import partial
from base64 import b64decode
from binascii import a2b_hex, b2a_hex


#------------- BASIC BYTESTRING MANIPULATION OPERATIONS ----------------

def int_to_bytes( i, n_bytes ):
    #converts a integer to n bytes (unsigned, big endian)
    return BitArray(uint=i, length=n_bytes*8).bytes

def bytes_to_int( bytes ):
    return int( b2a_hex(bytes), 16)

def zero_pad(s1,s2):
    #makes bytestrings the same size by zero padding the most significant bits
    swap= len(s1)>len(s2)
    if swap:
        s1,s2=s2,s1
    s1=s1.rjust( len(s2), b'\0' )
    if swap:
        s1,s2= s2,s1
    return s1,s2

def xor( *args ):
    '''xors two or more bytestrings'''
    if len(args)==1:
        return args[0]
    #s1,s2= zero_pad(args[0], xor(*args[1:])) #recursive
    #print "xoring", s1.encode('hex'), s2.encode('hex')
    #return "".join( chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))
    s1,s2= args[:2]
    return int_to_bytes( bytes_to_int(s1) ^ bytes_to_int(s2), max(len(s1), len(s2)))

def srtp_div(s1,s2):
    '''div (modulus) operation, as defined in https://tools.ietf.org/html/rfc3711#section-4.3.1.
    divs bytestrings'''
    s1,s2=   zero_pad(s1,s2)
    n_bytes= max(len(s1),len(s2))
    s1,s2=   bytes_to_int(s1), bytes_to_int(s2)
    tmp=     s1 % s2 if s2!=0 else 0
    return   int_to_bytes(tmp, n_bytes)


#------------- SRTP FUNCTIONS  ----------------
# python3
try: long
except: long = int

def aes_counter_encrypt( key, iv, data, decrypt=False):
    '''Basic AES en/decryption in counter mode'''
    assert type(iv) in (bytes,str,int,long)
    if type(iv)==str or type(iv) == bytes:
        iv = bytes_to_int(iv)
    counter= AESCounter.new( nbits=128, initial_value=iv)
    aes= AES.new(key=key, mode=AES.MODE_CTR, counter=counter )
    return aes.decrypt(data) if decrypt else aes.encrypt(data)

def srtp_packet_index( roc, seq, bytearray=False ):
    '''Calculates SRTP packet index given the Roll Over Counter and the
    RTP packet Sequence Number.
    https://tools.ietf.org/html/rfc3711#section-3.3.1'''
    result= roc*(2**16) + seq
    return result

def srtp_aes_counter_keystream( session_key, session_salt, packet_index, ssrc, keystream_size, counter_offset=0 ):
    '''Generates BYTE_SIZE bytes of keystream
    https://tools.ietf.org/html/rfc3711#section-4.1.1'''
    assert type(ssrc) in (int, long)
    assert type(packet_index) in (int, long)
    assert keystream_size <= 16 * 2**16 #128 bits per (AES) block, 2**16 blocks - this is the maximum RTP payload size
    assert keystream_size % 16 == 0 #keystream size  must be multiple of the AES block size
    assert len(session_salt)==112/8
    LOTS_OF_ZEROS= b'\0' * keystream_size
    ssrc=           int_to_bytes( ssrc, 4 )         #32 bits
    packet_index=   int_to_bytes( packet_index, 8)  #48 bits ROC + 16 bits SEQ
    counter_offset= int_to_bytes( counter_offset, 2 ) #this is for testing purposes only
    iv= xor(     session_salt+b'\0'*2,
                ssrc+b'\0'*8,
                packet_index+b'\0'*2,
                counter_offset ) #testing purposes only
    keystream= aes_counter_encrypt( session_key, iv, LOTS_OF_ZEROS )
    #print "keystream is", keystream.encode("hex")
    return keystream

def srtp_aes_counter_encrypt( session_key, session_salt, packet_index, ssrc, data, counter_offset=0 ):
    '''En/decrypts SRTP data using AES counter keystream.
    https://tools.ietf.org/html/rfc3711#section-4.1.1'''
    ds= len(data)
    keystream_size= ((ds/16)+1)*16 if (ds/16*16!=ds) else ds #nearest (upper-rounded) size to len(data) multiple of AES block size
    keystream= srtp_aes_counter_keystream( session_key, session_salt, packet_index, ssrc, keystream_size, counter_offset=0 )
    return xor(data, keystream[:ds])


def srtp_derive_key_aes_128( master_key, master_salt):
    '''SRTP key derivation, https://tools.ietf.org/html/rfc3711#section-4.3'''
    assert len(master_key)==128/8
    assert len(master_salt)==112/8
    CIPHER_LABEL=          int_to_bytes( 0, 1 )
    SALT_LABEL=            int_to_bytes( 2, 1 )
    AUTH_LABEL=            int_to_bytes( 1, 1 )
    KEY_DERIVATION_RATE=   int_to_bytes( 0, 6 )
    PACKET_INDEX=          int_to_bytes( 0, 6 )
    LOTS_OF_ZEROS=         b'\0'*32                   #for PRNG

    index_div_kdr= srtp_div( PACKET_INDEX, KEY_DERIVATION_RATE )
    multiply_2_16=         lambda x: x+b'\0\0' #multiply by 2^16
    prng=                  partial( aes_counter_encrypt, key=master_key, data=LOTS_OF_ZEROS )
    derive_key_from_label= lambda label : prng(iv=multiply_2_16(xor(master_salt, label+index_div_kdr)))

    cipher_key= derive_key_from_label(CIPHER_LABEL)[:16] #128 bits
    salt_key=   derive_key_from_label(SALT_LABEL)[:14]   #112 bits
    auth_key=   derive_key_from_label(AUTH_LABEL)[:20]   #??? not sure of size

    return cipher_key, salt_key, auth_key


#------------- TEST FUNCTIONS ----------------

def test_srtp_key_derivation_vectors():
    #test srtp_derive_key_aes_128
    master_key=  a2b_hex('E1F97A0D3E018BE0D64FA32C06DE4139')
    master_salt= a2b_hex('0EC675AD498AFEEBB6960B3AABE6')
    ck,sk,ak= srtp_derive_key_aes_128(master_key, master_salt)
    assert ck==a2b_hex('C61E7A93744F39EE10734AFE3FF7A087')
    assert sk==a2b_hex('30CBBC08863D8C85D49DB34A9AE1')
    assert ak.startswith(a2b_hex('CEBE321F6FF7716B6FD4AB49AF256A15')) # not sure of size

def test_srtp_aes_ctr_vectors():
    LOTS_OF_ZEROS= b'\0' * 16 * 2**16
    session_key= a2b_hex('2B7E151628AED2A6ABF7158809CF4F3C')
    session_salt= a2b_hex('F0F1F2F3F4F5F6F7F8F9FAFBFCFD')
    roc= 0
    seq= 0
    ssrc=0
    packet_i= srtp_packet_index(roc, seq)
    result= srtp_aes_counter_encrypt( session_key, session_salt, packet_i, ssrc, LOTS_OF_ZEROS)
    assert result[0x0000*16:0x0001*16]==a2b_hex('E03EAD0935C95E80E166B16DD92B4EB4')
    assert result[0x0001*16:0x0002*16]==a2b_hex('D23513162B02D0F72A43A2FE4A5F97AB')
    assert result[0x0002*16:0x0003*16]==a2b_hex('41E95B3BB0A2E8DD477901E4FCA894C0')
    assert result[0xfeff*16:0xff00*16]==a2b_hex('EC8CDF7398607CB0F2D21675EA9EA1E4')
    assert result[0xff00*16:0xff01*16]==a2b_hex('362B7C3C6773516318A077D7FC5073AE')
    assert result[0xff01*16:0xff02*16]==a2b_hex('6A2CC3787889374FBEB4C81B17BA6C44')

def run_tests():
    test_srtp_key_derivation_vectors()
    test_srtp_aes_ctr_vectors()

if __name__=='__main__':
    run_tests()
