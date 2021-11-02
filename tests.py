import sys
import hashlib
from P256 import generate_keypair, sign_data, verify_data

message="Paulius Norkus IFM-1/3"

if (len(sys.argv) > 1):
  message = (sys.argv[1])

# Generate Alice's key pair (PrK,PuK)
PrK, PuK = generate_keypair()

e = int(hashlib.sha256(message.encode()).hexdigest(), 16) # hashed message

# Alice signs hashed message "e" using her private key
# Returns values r, s
r, s = sign_data(e, PrK)

# To check signature Bob will use Alice's public key and values r, s
# Return values v - validation value, valid - true or false
v, valid = verify_data(e, PuK, r, s)

# Write results into a file
fileWrite = open("results.txt", "w")
fileWrite.write(f"Message: {message}\nMessage Hash: {hex(e)}\nAlice's private key = {hex(PrK)}\nAlice's public key = ({hex(PuK[0])}, {hex(PuK[1])})\n\nr = {hex(r)}\ns = {hex(s)}\nv = {hex(v)}\nVerified: {valid}")
fileWrite.close()
