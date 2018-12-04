#!/usr/bin/env python
from hashlib import md5,sha1,sha256
trans_5C = "".join(chr(x ^ 0x5c) for x in xrange(256))
trans_36 = "".join(chr(x ^ 0x36) for x in xrange(256))
md5_blocksize = md5().block_size
sha1_blocksize = sha1().block_size
sha256_blocksize = sha256().block_size

print "https://en.wikipedia.org/wiki/HMAC#Implementation"

def hmac_md5(key, msg):
    if len(key) > md5_blocksize:
        key = md5(key).digest()
    key += chr(0) * (md5_blocksize - len(key))
    o_key_pad = key.translate(trans_5C)
    i_key_pad = key.translate(trans_36)
    return md5(o_key_pad + md5(i_key_pad + msg).digest()).hexdigest()

def hmac_sha1(key,msg):
	if len(key) > sha1_blocksize:
		key = sha1(key).digest()
	key += chr(0)* (sha1_blocksize - len(key))
	o_key_pad = key.translate(trans_5C)
	i_key_pad = key.translate(trans_36)
	return sha1(o_key_pad+sha1(i_key_pad+msg).digest()).hexdigest()

def hmac_sha256(key,msg):
	if len(key) > sha256_blocksize:
		key = sha256(key).digest()
	key += chr(0)* (sha256_blocksize - len(key))
	o_key_pad = key.translate(trans_5C)
	i_key_pad = key.translate(trans_36)
	return sha256(o_key_pad+sha256(i_key_pad+msg).digest()).hexdigest()

if __name__ == "__main__":
	print "MD5: "+hmac_md5("key", "The quick brown fox jumps over the lazy dog")
	print "SHA1: "+hmac_sha1("key", "The quick brown fox jumps over the lazy dog")
	print "SHA256: "+hmac_sha256("key", "The quick brown fox jumps over the lazy dog")
