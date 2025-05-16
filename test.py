import os,base64

print(base64.b64encode(os.urandom(32)).decode())
print(base64.b64encode(os.urandom(16)).decode())
