import base64
from Crypto.Cipher import AES

#https://cryptopals.com/sets/1
#cha1-Convert hex to base64
def cha1():
    b16=bytearray('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'.decode('hex'))
    b64=base64.b64encode(b16)
    print(b64)
    assert(b64 == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

#cha2- Fixed XOR
def cha2_xor():
    # decode hex encoding to array of bytes
    barray1=bytearray('1c0111001f010100061a024b53535009181c'.decode('hex'))
    barray2=bytearray('686974207468652062756c6c277320657965'.decode('hex'))

    cipher = bytearray()

    #since both are in same size
    for i in range(len(barray1)):
        cipher.append(barray1[i] ^ barray2[i])

    #This XOR works for all cases
    cipherKey = bytearray()
    ciphertxt=bytearray('746865206b696420646f6e277420706c6179'.decode('hex'))
    for i in range(len(barray1)):
        cipherKey.append(barray1[i] ^ ciphertxt[i%len(ciphertxt)])

    print(str(cipherKey).encode('hex'))

    print(str(cipher).encode('hex'))
    assert(str(cipher).encode('hex') == '746865206b696420646f6e277420706c6179')

#cha3-Single-byte XOR cipher
def cha3():
    ciphertxt=bytearray('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'.decode('hex'))
    print(len(ciphertxt))
    plaintxt=bytearray()
    #key=34*'A'
    #keytxt=bytearray(key)
    single_keytxts=[]
    for k in range(256):
        single_keytxts.append(bytearray(chr(k)))

    for keytxt in single_keytxts:
        for i in range(len(ciphertxt)):
            plaintxt.append(keytxt[0] ^ ciphertxt[i])
        #print plaintxt
        #found a meaningful sentence on the plaintxt list
        if 'POUND' in str(plaintxt):
            print(keytxt)
        plaintxt=bytearray()

    keym=34*'x'
    keytxtm=bytearray(keym)
    for i in range(len(ciphertxt)):
        plaintxt.append(keytxtm[i] ^ ciphertxt[i])
    print(plaintxt)

#cha4-Detect single-character XOR
def cha4():

    filepath='ciphertxt_list.txt'
    cipherslist=[]

    single_keytxts=[]
    for k in range(256):
        single_keytxts.append(bytearray(chr(k)))

    #lines = tuple(open(filepath, 'r'))
    lines = open(filepath).read().split('\n')
    for line in lines:
        #print line
        cipherslist.append(bytearray(str(line).decode('hex')))
        #print bytearray(str(line).decode('hex'))

    plaintxt=bytearray()
    for ciphertxt in cipherslist:
        for keytxt in single_keytxts:
            for i in range(len(ciphertxt)):
                plaintxt.append(keytxt[0] ^ ciphertxt[i])
            if has_english_words(plaintxt):
                print("["+keytxt+"-"+plaintxt+"-"+str(ciphertxt).encode('hex')+"]")
            plaintxt =bytearray()

def has_english_words(text):
    most_frequent_words = ['the', 'and', 'have', 'that', 'for',
    'you', 'with', 'say', 'this', 'they', 'but', 'his', 'from',
    'that', 'not', "n't", 'she', 'what', 'their', 'can', 'who',
    'get', 'would', 'her', 'make', 'about', 'know', 'will',
    'one', 'time', 'there', 'year', 'think', 'when', 'which',
    'them', 'some', 'people', 'take', 'out', 'into','just', 'see',
    'him', 'your', 'come', 'could', 'now', 'than', 'like', 'other',
    'how', 'then', 'its', 'out', 'two', 'more ,these', 'want',
    'way', 'look', 'first', 'also', 'new', 'because', 'day',
    'more', 'use', 'man', 'find', 'here', 'thing', 'give', 'many']

    for word in most_frequent_words:
        if word in text:
            return True
    return False

#Implement repeating-key XOR
def cha5():
    plaintxt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    keytxt="ICE"
    bplaintxt = bytearray(plaintxt)
    bkeytxt = bytearray(keytxt)
    ciphertxt = bytearray()

    for i in range(len(bplaintxt)):
        ciphertxt.append(bplaintxt[i] ^ bkeytxt[i%len(bkeytxt)])
    print(str(ciphertxt).encode('hex'))

def cha6():
    plaintxt="longplaintext"
    keytxt="key"
    bplaintxt=bytearray(plaintxt)
    bkeytxt=bytearray(keytxt)
    result=bytearray()
    for i in range(len(bplaintxt)):
        result.append(bplaintxt[i]^bkeytxt[i%len(bkeytxt)])
    print(str(result).encode('hex')) #070a170c15150a0c171f00011f

    '''
    07 0a 17 0c 15 15 0a 0c 17 1f 00 01 1f
    k  e  y  k  e  y  k  e  y  k  e  y  k

    k  e  y
    07 0a 17
    0c 15 15
    0a 0c 17
    1f 00 01
    1f

    k=07 0c 0a 1f 1f
    e=0a 15 0c 00
    y=17 15 17 01
    '''

    ciphertxt= bytearray('070c0a1f1f'.decode('hex'))
    keytxt=bytearray('k')
    res=bytearray()
    for j in range(len(ciphertxt)):
        res.append(ciphertxt[j]^keytxt[j%len(keytxt)])
    print(str(res))

    ################
    str1=bytearray('this is a test')
    str2=bytearray('wokka wokka!!!')
    res2=bytearray()
    for k in range(len(str1)):
        res2.append(str1[k]^str2[k])
    print(bin(int(str(res2).encode('hex'),16)).count('1'))

def cha7():
    key="YELLOW SUBMARINE"

    filepath='ciphertxt_list.txt'
    cipherslist=[]
    decipher = AES.new(key, AES.MODE_ECB)
    lines = open(filepath).read().split('\n')
    for line in lines:
        print(decipher.decrypt(base64.b64decode(line)))




if __name__ == "__main__":
    #cha1()
    #cha2_xor()
    #cha3()
    #cha4()
    #cha5()
    #cha6()
    cha7()
