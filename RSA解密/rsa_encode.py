import gmpy2
import sys
import sys
from Crypto.PublicKey import RSA


def calc_private_key():
    rsa_n1 = 86934482296048119190666062003494800588905656017203025617216654058378322103517
    p = gmpy2.mpz(304008741604601924494328155975272418463)
    q = gmpy2.mpz(285960468890451637935629440372639283459)
    e = gmpy2.mpz(65537)
    u = ~p % q

    phi_n = (p - 1) * (q - 1)
    if phi_n != 0:
        d = gmpy2.invert(e, phi_n)
        keypair = RSA.RsaKey(n=rsa_n1, e=e, d=d, p=p, q=q, u=u)
        private = open('private.pem','wb')
        private.write(keypair.exportKey() + b"\n") 
        private.close()
        print ("成功生成私钥文件 ： private.pem")
        sys.exit(0)
        
calc_private_key()

