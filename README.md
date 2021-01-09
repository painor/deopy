# Deopy

### Short description
A python library that helps you de-obfuscate/decrypt obfuscated python code


# WARNING! Read Before Using

This library uses a lot of exec to reverse the code which is also dangerous and can be easily exploited. Do not run it with code you don't trust. You are the only one responsible if something bad happens to your marchine.

# How to install?
You can either install the latest from source <br> `pip install git+https://github.com/painor/deopy.git` <br> or from pip <br> `pip install deopy`

### How to use
Deopy offers a lot of different deobfuscation techniques and can even detect them. 
```
from deopy import Deopy
import logging
# tells you more information like how many times it was deobfuscated
logging.basicConfig(level=logging.INFO)
# The obfusated code. needs to be a string
data = """
import marshal as m
data = m.loads(b'\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00@\x00\x00\x00s\x1a\x00\x00\x00e\x00d\x00\x83\x01D\x00]\x0cZ\x01e\x02e\x01\x83\x01\x01\x00q\x08d\x01S\x00)\x02\xe9d\x00\x00\x00N)\x03\xda\x05range\xda\x01i\xda\x05print\xa9\x00r\x05\x00\x00\x00r\x05\x00\x00\x00\xda\x06string\xda\x08<module>\x01\x00\x00\x00s\x02\x00\x00\x00\x0c\x01')
exec(data)
"""
# instantiate the class
d = Deopy(verbose=True)
# We know that the technique that is used was marshal.
# so we can call it directly
print(d.decrypt_marshal(data))

```
Deopy also offers `d.auto_decrypt(data)` which will try to decrypt the data until it no longer can. This is useful for code that is obfuscated multiple times

### Long description
with the rise of popularity of python a lot of people are starting to release their code in an obfuscated way which is dangerous as they could contain malicious code in them. The goal of this library is to reverse the automated obfuscators out there.


### Issues
Currently, the library can only reverse very specific obfuscation methods (that can break in the future). If you found a new method please open either a PR or an issue.

### Contributing
There isn't any code of conduct up yet since it's still a fairly smpall library but commenting your code is heavily encouraged for future contributors