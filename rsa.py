import gmpy2
from Crypto.PublicKey import RSA
import subprocess
import argparse
import sys
import os
from factordb.factordb import FactorDB

##############################低解密指数攻击######################################
# 使用辗转相处将分数 x/y 转为连分数的形式
def transform(x, y):
    res = []
    while y:
        res.append(x // y)
        x, y = y, x % y
    return res
    
def continued_fraction(sub_res):
    numerator, denominator = 1, 0
    # 从sublist的后面往前循环
    for i in sub_res[::-1]:
        denominator, numerator = numerator, i * numerator + denominator
        
    # 得到渐进分数的分母和分子，并返回
    return denominator,numerator

# 求解每个渐进分数
def sub_fraction(x, y):
    res = transform(x, y)
    # 将连分数的结果逐一截取以求渐进分数
    res = list(map(continued_fraction, (res[0:i] for i in range(1, len(res)))))
    return res

# 由 p + q 和 p * q 的值通过维达定理来求解 p 和 q
def get_pq(a, b, c):
    #由上述可得，开根号一定是整数，因为有解
    par = gmpy2.isqrt(b * b - 4 * a * c)
    x1, x2 = (-b + par) // (2 * a), (-b - par) // (2 * a)
    return x1, x2

# 低解密指数攻击（维达攻击）
def wienerAttack(e, n):
    d = 0
    # 用一个for循环来注意试探 e/n 的连续函数的渐进分数，直到找到一个满足条件的渐进分数
    for (d, k) in sub_fraction(e, n):
        # 可能会出现连分数的第一个为0的情况，排除
        if k == 0:
            continue
        
        #ed=1 (mod φ(n)) 因此如果找到了d的话，(ed-1)会整除φ(n), 也就是存在k使得(e*d-1) // k = φ(n)
        if (e * d - 1) % k != 0:
            continue
        
        # 这个结果就是 φ(n)
        phi_n = (e * d - 1) // k
        px ,qy=get_pq(1, n - phi_n + 1, n)
        if px * qy == n:
            # 可能会得到两个负数，负负得正未尝不会出现
            p, q = abs(int(px)), abs(int(qy))
            
            #求ed=1 (mod  φ(n))的结果，也就是e关于 φ(n)的乘法逆元d
            d = gmpy2.invert(e, (p - 1) * (q - 1))
            break
    return d
#################################################################################

# 大素数分解
def big_num_resolve(data):
    factor = FactorDB(data)
    factor.connect()
    factor_list = factor.get_factor_list()
    return factor_list

# 计算获取私钥
def calc_private_key(rsa_para, priv_file=False):
    rsa_u = ~rsa_para["p"] % rsa_para["q"]
    phi_n = (rsa_para["p"] - 1) * (rsa_para["q"] - 1)
    
    if phi_n != 0:
        rsa_para["d"] = gmpy2.invert(rsa_para["e"], phi_n)
        keypair = RSA.RsaKey(n=rsa_para["n"], e=rsa_para["e"], d=rsa_para["d"], p=rsa_para["p"], q=rsa_para["q"], u=rsa_u)
        if priv_file == True:
            with open("private.pem", "wb") as fp:
                fp.write(keypair.export_key())
                print ("成功生成私钥 : private.pem")


# 通过dp或dq求d
def calc_dp_or_dq(rsa_para, rsa_dp, rsa_dq):
    if rsa_dp != None:
        rsa_dp_dq = rsa_dp
    if rsa_dp != None:
        rsa_dp_dq = rsa_dq
    
    for i in range(1, rsa_para["e"]):
        if rsa_para["e"] * rsa_dp_dq % i == 1:
            rsa_para["p"] = (rsa_para["e"] * rsa_dp_dq - 1) // i + 1
            if rsa_para["n"] % rsa_para["p"] != 0:
                continue
            rsa_para["q"] = rsa_para["n"] // rsa_para["p"]
            phi_n = (rsa_para["p"] - 1) * (rsa_para["q"] - 1)
            rsa_para["d"] = gmpy2.invert(rsa_para["e"], phi_n)

# 通过dp和dq直接获取明文
def calc_dp_and_dq(rsa_para, enc_data, rsa_dp, rsa_dq):
    print (rsa_para, enc_data, rsa_dp, rsa_dq)
    m1 = pow(enc_data, rsa_dp, rsa_para["p"])
    m2 = pow(enc_data, rsa_dq, rsa_para["q"])
    u = gmpy2.invert(rsa_para["q"], rsa_para["p"])
    plain_text = (((m1 - m2) * u) % rsa_para["p"]) * rsa_para["q"] + m2
    
    print ("明文 (m)  : " + str(plain_text))
    
# 小指数爆破直接获取明文
def small_index_crack(rsa_para, enc_data, len=1000):
    for i in range(1000):
        result = gmpy2.iroot(enc_data+i*rsa_para["n"], rsa_para["e"])
        if result[1] == True:
            print ("明文 (m)  : " + str(result[0]))
            break

# 共模攻击
def common_mode_attack(n, c1, c2, e1, e2):
    s = gmpy2.gcdext(e1, e2)
    s1 = s[1]
    s2 = s[2]
    
    plain_text = pow(c1, s1, n) * pow(c2, s2, n) % n
    print ("明文 (m)  : " + str(plain_text))

# 解密
def decrypt_rsa_enc(rsa_para, enc_file=None, enc_data=None):
    if enc_file != None:
        if (os.path.exists("private.pem") == True) and (os.path.exists(args.enc_file) == True):
            command = "openssl rsautl -decrypt -in " + args.enc_file + " -inkey private.pem"
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print ("明文 (m)  : " + result.stdout.read().decode())
        else:
            print ("解密文件失败  : 缺少私钥文件或者加密文件不存在！")
            sys.exit(0)
                
    if enc_data != None:
        rsa_c = gmpy2.mpz(enc_data)
        rsa_m = pow(rsa_c, rsa_para["d"], rsa_para["n"])
        print ("明文 (m)  : " + str(rsa_m))

def usage():
    info = """
    RSA私钥破解程序
    mode 1 : 已知n、e，暴力破解q、p，获取私钥d
    mode 2 : 已知p、q，获取私钥d
    mode 3 : 已知n，通过dp或dq，破解私钥d
    mode 4 : 已知p、q，通过dp或dq，破解私钥d
    mode 5 : 低加密指数攻击
    mode 6 : 共模攻击
    mode 7 : 低解密指数攻击
    """
    print (info)

if __name__ == '__main__':
    rsa_para = {"n": 0, "e": 0, "p": 0, "q": 0, "d": 0}
    usage()
    parser = argparse.ArgumentParser()
    parser.add_argument('-mode', '--dec_mode', default=None, help="choose attack mode")
    
    parser.add_argument('-enc_file', '--enc_file', default=None)
    parser.add_argument('-in_key', '--public_key', default=None)
    parser.add_argument('-out_key', '--private_key', action='store_true', default=False)
    
    parser.add_argument('-n', '--rsa_n', default=None)
    parser.add_argument("-e", '--rsa_e', default=None)
    parser.add_argument("-p", '--rsa_p', default=None)
    parser.add_argument("-q", '--rsa_q', default=None)
    parser.add_argument('-c', '--rsa_c', default=None)
    parser.add_argument("-dp", '--rsa_dp', default=None)
    parser.add_argument("-dq", '--rsa_dq', default=None)
    args = parser.parse_args()
    
    if args.dec_mode != None:
        # 模式1：已知n、e，暴力破解q、p
        if int(args.dec_mode) == 1:
            if args.public_key != None:
                if os.path.exists(args.public_key) == True:
                    with open(args.public_key, "r") as fp:
                        public_key = fp.read()

                    rsa_key_info = RSA.importKey(public_key)
                    rsa_para["n"] = rsa_key_info.n
                    rsa_para["e"] = rsa_key_info.e
                else:
                    print ("Not Find Public Key File.")
                    sys.exit(0)
            elif (args.rsa_n != None) and (args.rsa_e != None):
                    rsa_para["n"] = gmpy2.mpz(args.rsa_n)
                    rsa_para["e"] = gmpy2.mpz(args.rsa_e)
            else:
                print ("lack parameter.")
                sys.exit(0)

            factor_list = big_num_resolve(rsa_para["n"])
                
            if len(factor_list) >= 2:
                rsa_para["q"] = factor_list[0]
                rsa_para["p"] = factor_list[1]
            else:
                print ("Not Find parameter p and q.")
                sys.exit(0)
            
            rsa_d = calc_private_key(rsa_para, args.private_key)
        elif int(args.dec_mode) == 2:
            if (args.rsa_q != None) and (args.rsa_p != None) and (args.rsa_e != None):
                rsa_para["e"] = gmpy2.mpz(args.rsa_e)
                rsa_para["q"] = gmpy2.mpz(args.rsa_q)
                rsa_para["p"] = gmpy2.mpz(args.rsa_p)
                rsa_para["n"] = rsa_para["q"] * rsa_para["p"]
            elif (args.rsa_q != None) and (args.rsa_n != None) and (args.rsa_e != None):
                rsa_para["e"] = gmpy2.mpz(args.rsa_e)
                rsa_para["q"] = gmpy2.mpz(args.rsa_q)
                rsa_para["n"] = gmpy2.mpz(args.rsa_n)
                rsa_para["p"] = rsa_para["n"] // rsa_para["q"]
            else:
                print ("lack parameter.")
                sys.exit(0)
                
            rsa_d = calc_private_key(rsa_para, args.private_key)
        elif int(args.dec_mode) == 3:
            if ((args.rsa_dp != None) or (args.rsa_dq != None)) and (args.rsa_n != None) and (args.rsa_e != None):
                rsa_para["n"] = gmpy2.mpz(args.rsa_n)
                rsa_para["e"] = gmpy2.mpz(args.rsa_e)
                rsa_dp = args.rsa_dp
                rsa_dq = args.rsa_dq
            else:
                print ("lack parameter.")
                sys.exit(0)
                
            rsa_info = calc_dp_or_dq(rsa_para, rsa_dp=rsa_dp, rsa_dq=rsa_dq)
            if len(rsa_info) == 3:
                rsa_para["p"] = rsa_info[0]
                rsa_para["q"] = rsa_info[1]
                rsa_d = rsa_info[2]

        elif int(args.dec_mode) == 4:
            if (args.rsa_dp != None) and (args.rsa_dq != None) and (args.rsa_p != None) and (args.rsa_q != None) and (args.rsa_c != None):
                rsa_para["q"] = gmpy2.mpz(args.rsa_q)
                rsa_para["p"] = gmpy2.mpz(args.rsa_p)
                rsa_dp = gmpy2.mpz(args.rsa_dp)
                rsa_dq = gmpy2.mpz(args.rsa_dq)
                rsa_c = gmpy2.mpz(args.rsa_c)
            else:
                print ("lack parameter.")
                sys.exit(0)
                
            calc_dp_and_dq(rsa_para, rsa_c, rsa_dp=rsa_dp, rsa_dq=rsa_dq)
            sys.exit(0)
        elif int(args.dec_mode) == 5:
            if (args.rsa_n != None) and (args.rsa_e != None) and (args.rsa_c != None):
                rsa_para["n"] = gmpy2.mpz(args.rsa_n)
                rsa_para["e"] = gmpy2.mpz(args.rsa_e)
                rsa_c = gmpy2.mpz(args.rsa_c)
                
                small_index_crack(rsa_para, rsa_c)
                sys.exit(0)
        elif int(args.dec_mode) == 6:
            if (args.rsa_n != None) and (args.rsa_e != None) and (args.rsa_c != None):
                rsa_n = gmpy2.mpz(args.rsa_n)
                rsa_e1 = gmpy2.mpz(args.rsa_e)
                rsa_c1 = gmpy2.mpz(args.rsa_c)
                
                rsa_e2 = gmpy2.mpz(input("input e2 : "))
                rsa_c2 = gmpy2.mpz(input("input c2 : "))
                
                common_mode_attack(rsa_n, rsa_c1, rsa_c2, rsa_e1, rsa_e2)
                sys.exit(0)
        elif int(args.dec_mode) == 7:
            if (args.rsa_n != None) and (args.rsa_e != None):
                rsa_n = gmpy2.mpz(args.rsa_n)
                rsa_e = gmpy2.mpz(args.rsa_e)
                
                rsa_d = wienerAttack(rsa_e, rsa_n)
                if rsa_d != 0:
                    print ("私钥 (d)  : " + str(rsa_d))
                else:
                    print ("无法解出私钥 (d)")
                sys.exit(0)
        else:
            print ("rsa decrypt mode choose error.")
            sys.exit(0)

        if rsa_para["d"] == 0:
            print ("Generate Private Key Failed.")
            sys.exit(0)
        
        print ("模数 (n)  : " + str(rsa_para["n"]))
        print ("指数 (e)  : " + str(rsa_para["e"]))
        print ("素数 (q)  : " + str(rsa_para["q"]))
        print ("素数 (p)  : " + str(rsa_para["p"]))
        print ("私钥 (d)  : " + str(rsa_para["d"]))
        
        decrypt_rsa_enc(rsa_para, enc_file=args.enc_file, enc_data=args.rsa_c)