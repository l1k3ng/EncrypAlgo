from Crypto.PublicKey import RSA
import subprocess
import argparse
import sys
import os
from factordb.factordb import FactorDB
import gmpy2

# 大素数分解
def big_num_resolve(data):
    factor = FactorDB(data)
    factor.connect()
    factor_list = factor.get_factor_list()
    
    return factor_list

# 计算获取私钥
def calc_private_key(rsa_n, rsa_e, rsa_p, rsa_q):
    rsa_u = ~rsa_p % rsa_q
    phi_n = (rsa_p - 1) * (rsa_q - 1)
    
    if phi_n != 0:
        rsa_d = gmpy2.invert(rsa_e, phi_n)
        keypair = RSA.RsaKey(n=rsa_n, e=rsa_e, d=rsa_d, p=rsa_p, q=rsa_q, u=rsa_u)
        private_key = keypair.export_key()
    else:
        private_key = None

    return private_key

def calc_rsa_dp(rsa_n, rsa_e, rsa_dp, enc_data):
    PlainText = 0
    for i in range(1, rsa_e):
        if rsa_e * rsa_dp % i == 1:
            rsa_p = (rsa_e * rsa_dp - 1) // i + 1
            if rsa_n % rsa_p != 0:
                continue
            rsa_q = rsa_n // rsa_p
            phi_n = (rsa_p - 1) * (rsa_q - 1)
            rsa_d = gmpy2.invert(rsa_e, phi_n)
            PlainText = pow(enc_data, rsa_d, rsa_n)

            if len(hex(PlainText)[2:]) % 2 == 1:
                continue

    if PlainText != 0:
        PlainText = bytes.fromhex(hex(PlainText)[2:])
        print (PlainText)
        
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-key', '--public_key', default=None)
    parser.add_argument('-enc_file', '--enc_file', default=None)
    parser.add_argument('-enc_data', '--enc_data', default=None)
    parser.add_argument('-rsa_n', '--rsa_n', default=None)
    parser.add_argument("-rsa_e", '--rsa_e', default=None)
    parser.add_argument("-rsa_p", '--rsa_p', default=None)
    parser.add_argument("-rsa_q", '--rsa_q', default=None)
    parser.add_argument("-rsa_dp", '--rsa_dp', default=None)
    args = parser.parse_args()
    
    if (args.rsa_dp != None) and (args.enc_data != None):
        if (args.rsa_n != None) and (args.rsa_e != None):
            rsa_n = gmpy2.mpz(args.rsa_n)
            rsa_e = gmpy2.mpz(args.rsa_e)
            rsa_dp = gmpy2.mpz(args.rsa_dp)
            enc_data = gmpy2.mpz(args.enc_data)
            calc_rsa_dp(rsa_n, rsa_e, rsa_dp, enc_data)

    if (args.rsa_n == None) or (args.rsa_e == None):
        if args.public_key != None:
            with open(args.public_key, "r") as fp:
                public_key = fp.read()

            rsa_key_info = RSA.importKey(public_key)
            rsa_n = rsa_key_info.n
            rsa_e = rsa_key_info.e
        else:
            print ("Not Find Public Key Info.")
            sys.exit(0)
    else:
        rsa_n = gmpy2.mpz(args.rsa_n)
        rsa_e = gmpy2.mpz(args.rsa_e)

    if (args.rsa_p == None) or (args.rsa_q == None):
        factor_list = big_num_resolve(rsa_n)

        if len(factor_list) >= 2:
            rsa_q = factor_list[0]
            rsa_p = factor_list[1]
        else:
            print ("Not Find parameter p and q.")
            sys.exit(0)
    else:
        rsa_q = gmpy2.mpz(args.rsa_q)
        rsa_p = gmpy2.mpz(args.rsa_p)

    private_key = calc_private_key(rsa_n, rsa_e, rsa_p, rsa_q)

    if (private_key != None) and (args.enc_file != None):
        with open("private.pem", "wb") as fp:
            fp.write(private_key)
        
        if (os.path.exists("private.pem") == True) and (os.path.exists(args.enc_file) == True):
            command = "openssl rsautl -decrypt -in " + args.enc_file + " -inkey private.pem"
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print (result.stdout.read().decode())
