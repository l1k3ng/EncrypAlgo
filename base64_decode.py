# [===============解密base64===============]
# 
# 程序输入：base64加密的字符串
# 程序输出：十六进制字符串

import base64

def ByteToHex(bins):
    return ''.join( [ "%02X" % x for x in bins ] ).strip()

if __name__ == "__main__":

    test_date = input("> ")
    
    bytes_value = base64.b64decode(test_date)
    hexs_value = ByteToHex(bytes_value)
    print (hexs_value)