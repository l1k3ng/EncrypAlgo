## 0x001 RSA加密算法相关公式

```
C = M ^ e mod n

M = C ^ d mod n

n = p * q

f(n) = (p - 1) * (q - 1)

1 < e < f(n)

d * e == 1 mod f(n)
```

其中C代表密文，M代表明文

## 0x002 RSA解密方式1-已知公钥或模数n和指数e

### 大数分解

要想获取私钥，首先需要对公钥的模数进行大数分解，分解成两个大素数。

大数分解有很多种方式，这里列举三种：
1. 通过在线工具 **http://www.factordb.com/** 
2. 离线工具 **cado-nfs**
    ```
    ./cado-nfs.py （十进制数）
    ```
3. python3模块（pip3 install factordb-pycli）

### 计算私钥d

当知道n、e、q、p后，即可计算出私钥d

因为 **f(n) = (q - 1) * (p - 1)**， **d * e = 1 mod f(n)**

所以 **d为e关于f(n)的乘法逆元**， 通过求逆元的方式即可获取 **d** 值。

可通过python3 gmpy2库计算

```
rsa_d = gmpy2.invert(rsa_e, phi_n)
```

### 通过私钥文件解密

解密加密文本可通过openssl的命令获得明文

```
openssl rsautl -decrypt -in flag.enc -inkey private.pem
```

## 0x003 RSA解密方式2-已知dq或dp、n、e

```
dp = d mod (p - 1)
dq = d mod (q - 1)
```

## 0x004 RSA解密方式3-已知dq、dp、p、q

根据公式

```
m1 = c ^ dp mod p
m2 = c ^ dq mod q
u = q ^ -1 mod p
M = (((m1 - m2) * u) mod p) * q + m2
```

可直接通过dp、dq、p、q解密获取明文

1. 计算 q mod p 的逆元 u
2. 计算 m1 = (c ^ dp) mod p
3. 计算 m2 = (c ^ dq) mod q
4. M = (((m1 - m2) * u) mod p) * q + m2

## 0x005 RSA解密方式4-共模攻击



## 0x006 RSA解密方式5-小指数明文爆破

## 0x006 综合解密脚本

见附件：rsa.py