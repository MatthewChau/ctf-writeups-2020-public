from pwn import *

# Credit to giuscri at https://gist.github.com/giuscri/a6035b7648b3315fbe352fe45854f3a5
def detect_ecb(plaintext, ciphertext):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext) - 16, 16)]
    increment_chunk_counter = lambda d, b: (b in d and (d.__setitem__(b, d[b] + 1) or d)) or (d.__setitem__(b, 1) or d)
    items = list(reduce(increment_chunk_counter, blocks, {}).items())
    items.sort(key=lambda p: p[1], reverse=True)
    if len(plaintext) // 16 - items[0][1] < 2:
        return "ECB\n"
    else:
        return "CBC\n"
        

plain = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"

s = remote("crypto.chal.csaw.io",5001)

flag = s.recv()

for x in range(0,202):
    try:
        s.send(plain)
        cipher = s.recv()
        det = detect_ecb(plain,cipher[16:144])
        print(det[:1] + " ")
        s.send(det)
        flag = s.recv()
    except Exception as err:
        print(err)
        break