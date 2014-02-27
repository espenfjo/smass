import os
import hashlib
import binascii
import pydeep
import magic

class Hash(object):

    def __init__(self, artifact):
        self.artifact = artifact.data
        self.hashes = {}
        self.get_hashes()

    def get_chunks(self):
        fd = open(self.artifact, 'rb')
        while True:
            chunk = fd.read(16 * 1024)
            if not chunk:
                break

            yield chunk

        fd.close()


    def get_hashes(self):
        crc = 0
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        crc = binascii.crc32(self.artifact, crc)
        md5.update(self.artifact)
        sha1.update(self.artifact)
        sha256.update(self.artifact)
        sha512.update(self.artifact)

        self.hashes['crc32'] = ''.join('%02X' % ((crc>>i)&0xff) for i in [24, 16, 8, 0])
        self.hashes['md5'] = md5.hexdigest()
        self.hashes['sha1'] = sha1.hexdigest()
        self.hashes['sha256'] = sha256.hexdigest()
        self.hashes['sha512'] = sha512.hexdigest()
        self.hashes['ssdeep'] = pydeep.hash_buf(self.artifact)
