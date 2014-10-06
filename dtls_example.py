CIPHER_KEY_LENGTH = (128  / 8)
CIPHER_SALT_LENGTH = (112 / 8)

import itertools
from base64 import b64encode

from srtp_decryption import srtp_aes_counter_encrypt, srtp_packet_index, srtp_derive_key_aes_128

key_dump= \
'''16:33:03.024 I  17776 C:0          DTLS key: 206
16:33:03.024 I  17776 C:0          DTLS key: 23
16:33:03.024 I  17776 C:0          DTLS key: 241
16:33:03.024 I  17776 C:0          DTLS key: 84
16:33:03.024 I  17776 C:0          DTLS key: 148
16:33:03.024 I  17776 C:0          DTLS key: 13
16:33:03.024 I  17776 C:0          DTLS key: 134
16:33:03.024 I  17776 C:0          DTLS key: 143
16:33:03.024 I  17776 C:0          DTLS key: 225
16:33:03.024 I  17776 C:0          DTLS key: 158
16:33:03.024 I  17776 C:0          DTLS key: 18
16:33:03.024 I  17776 C:0          DTLS key: 129
16:33:03.024 I  17776 C:0          DTLS key: 126
16:33:03.024 I  17776 C:0          DTLS key: 136
16:33:03.024 I  17776 C:0          DTLS key: 117
16:33:03.024 I  17776 C:0          DTLS key: 182
16:33:03.024 I  17776 C:0          DTLS key: 2
16:33:03.024 I  17776 C:0          DTLS key: 127
16:33:03.024 I  17776 C:0          DTLS key: 19
16:33:03.024 I  17776 C:0          DTLS key: 178
16:33:03.024 I  17776 C:0          DTLS key: 79
16:33:03.024 I  17776 C:0          DTLS key: 85
16:33:03.024 I  17776 C:0          DTLS key: 120
16:33:03.025 I  17776 C:0          DTLS key: 194
16:33:03.025 I  17776 C:0          DTLS key: 215
16:33:03.025 I  17776 C:0          DTLS key: 112
16:33:03.025 I  17776 C:0          DTLS key: 70
16:33:03.025 I  17776 C:0          DTLS key: 212
16:33:03.025 I  17776 C:0          DTLS key: 215
16:33:03.025 I  17776 C:0          DTLS key: 177
16:33:03.025 I  17776 C:0          DTLS key: 61
16:33:03.025 I  17776 C:0          DTLS key: 42
16:33:03.025 I  17776 C:0          DTLS key: 141
16:33:03.025 I  17776 C:0          DTLS key: 171
16:33:03.025 I  17776 C:0          DTLS key: 194
16:33:03.025 I  17776 C:0          DTLS key: 178
16:33:03.025 I  17776 C:0          DTLS key: 53
16:33:03.025 I  17776 C:0          DTLS key: 29
16:33:03.025 I  17776 C:0          DTLS key: 167
16:33:03.025 I  17776 C:0          DTLS key: 214
16:33:03.025 I  17776 C:0          DTLS key: 217
16:33:03.025 I  17776 C:0          DTLS key: 149
16:33:03.025 I  17776 C:0          DTLS key: 167
16:33:03.025 I  17776 C:0          DTLS key: 3
16:33:03.025 I  17776 C:0          DTLS key: 168
16:33:03.025 I  17776 C:0          DTLS key: 170
16:33:03.025 I  17776 C:0          DTLS key: 130
16:33:03.025 I  17776 C:0          DTLS key: 126
16:33:03.025 I  17776 C:0          DTLS key: 52
16:33:03.025 I  17776 C:0          DTLS key: 70
16:33:03.025 I  17776 C:0          DTLS key: 13
16:33:03.025 I  17776 C:0          DTLS key: 52
16:33:03.025 I  17776 C:0          DTLS key: 80
16:33:03.025 I  17776 C:0          DTLS key: 12
16:33:03.025 I  17776 C:0          DTLS key: 29
16:33:03.025 I  17776 C:0          DTLS key: 53
16:33:03.025 I  17776 C:0          DTLS key: 153
16:33:03.025 I  17776 C:0          DTLS key: 132
16:33:03.025 I  17776 C:0          DTLS key: 172
16:33:03.025 I  17776 C:0          DTLS key: 193
'''

rtp_payload_hex= \
'694d145c84dcd91ebcb0b02727196f1655c6c904baf26b3c66474561290e8e75d6700922b307c254c23d053ddb09455f7972f8b6bb0d33151b772c1f0b515fe55a637c0e6104c1601cb70fde0865687bf077ec5dfbaeb899c1ba81dac384c308ac9ce8204100919a6387d6e6d7e9fcd8a45d9491afb250d87a311607b0f603587053ff261ca3379509b50fc70f2038757dad70befba8411d38d446c6bb8564f9dedaf1afdf6466346b55'


keying_material= "".join(chr( int(line[line.rindex(" "):])) for line in key_dump.splitlines())
assert len(keying_material)==CIPHER_KEY_LENGTH*2+CIPHER_SALT_LENGTH*2

rtp_payload= rtp_payload_hex.decode('hex')

print "rtp payload size",len(rtp_payload)

ck_i=CIPHER_KEY_LENGTH*0 + CIPHER_SALT_LENGTH*0
sk_i=CIPHER_KEY_LENGTH*1 + CIPHER_SALT_LENGTH*0
cs_i=CIPHER_KEY_LENGTH*2 + CIPHER_SALT_LENGTH*0
ss_i=CIPHER_KEY_LENGTH*2 + CIPHER_SALT_LENGTH*1

client_master_key= keying_material[ ck_i : ck_i + CIPHER_KEY_LENGTH]
server_master_key= keying_material[ sk_i : sk_i + CIPHER_KEY_LENGTH]
client_master_salt= keying_material[ cs_i : cs_i + CIPHER_SALT_LENGTH]
server_master_salt= keying_material[ ss_i : ss_i + CIPHER_SALT_LENGTH]



#k,s= master_k, master_s

print "\nCLIENT"
master_k, master_s= client_master_key, client_master_salt   #We are the client
print "master key is ",master_k.encode('hex')
print "master salt is ",master_s.encode('hex')
print "SDES:", b64encode(master_k+master_s)
k,s,a = srtp_derive_key_aes_128(master_k,master_s) 
print "derived key is ",k.encode('hex')
print "derived salt is ",s.encode('hex')
print "derived auth is ",a.encode('hex')

print "\nSERVER"
master_k, master_s= server_master_key, server_master_salt   #We are the server
print "master key is ",master_k.encode('hex')
print "master salt is ",master_s.encode('hex')
print "SDES:", b64encode(master_k+master_s)
k,s,a = srtp_derive_key_aes_128(master_k,master_s) 
print "derived key is ",k.encode('hex')
print "derived salt is ",s.encode('hex')
print "derived auth is ",a.encode('hex')

'''
ssrc= 0x0aeed995
seq= 6391
roc= 0 #always starts at 0

packet_i= srtp_packet_index(roc, seq)
print "rtp payload size",len(rtp_payload)

plaintext= srtp_aes_counter_encrypt( k, s, packet_i, ssrc, rtp_payload )

print rtp_payload.encode('hex')
print plaintext.encode('hex')

#import pylab
#pylab.plot( map(ord, rtp_payload) )
#pylab.plot( map(ord, plaintext) )
#pylab.show()
'''
