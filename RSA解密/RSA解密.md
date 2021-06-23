## 0x001 获取参数

可以通过网站 **http://tool.chacuo.net/cryptrsakeyparse** 解析

![](1.png)


也可以通过openssl命令获取解析

```
openssl rsa -pubin -text -modulus -in warmup -in pub.key
```

![](2.png)

这里就可以获取到指数（Exponent）和模数(Modulus)

## 0x002 大数分解

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

## 0x003 生成私钥

生成私钥可通过python3脚本获取

```

```

## 0x004 解密

解密加密文本同样可通过openssl和python脚本的方式获得明文

1. openssl

    ```
    openssl rsautl -decrypt -in flag.enc -inkey private.pem
    ```

2. python3

    ```

    ```

## 0x005 综合解密脚本

```
```