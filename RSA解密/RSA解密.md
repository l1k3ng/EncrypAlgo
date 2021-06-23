## 0x001 RSA加密算法相关公式

> 加密：C = M ^ e mod n

> 解密：M = C ^ d mod n

其中C代表密文，M代表明文

```
n = p * q   # p和q代表两个大素数
dp = d mod (p - 1)
dq = d mod (q - 1)
```

## 0x002 RSA解密方式1-私钥解密

### 大数分解

要想获取私钥，首先需要对公钥的模数进行大数分解，分解成两个大素数。

大数分解有很多种方式，这里列举三种：
1. 通过在线工具 **http://www.factordb.com/** 
2. 离线工具 **cado-nfs**
    ```
    ./cado-nfs.py 86934482296048119190666062003494800588905656017203025617216654058378322103517（十进制数）
    ```

3. python3模块（pip3 install factordb-pycli）

    ```
    from factordb.factordb import FactorDB
    factor = FactorDB(86934482296048119190666062003494800588905656017203025617216654058378322103517)
    factor.connect()
    factor_list = factor.get_factor_list()
    ```

    factor_list即为分解出的质数集合的表

## 生成私钥

生成私钥可通过python3脚本获取

```
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
```

## 解密

解密加密文本可通过openssl的命令获得明文

```
openssl rsautl -decrypt -in flag.enc -inkey private.pem
```

## 0x003 RSA解密方式2-泄漏dq或dp

## 0x004 RSA解密方式3-共模攻击

## 0x005 RSA解密方式4-攻击

## 0x006 综合解密脚本

见附件：rsa.py