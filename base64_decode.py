# [===============解密base64===============]
# 
# 程序输入：base64加密的字符串
# 程序输出：十六进制字符串

import base64
import sys

test_data = "MCgCIQDAMyxcZK5HGC9sHIdtQjNpEFRaWPfu/vwLyq9a80HM3QIDAQAB"

def ByteToHex(bins):
    return ''.join( [ "%02X" % x for x in bins ] ).strip()

if __name__ == "__main__":

    # if len(sys.argv) < 2:
    #     print("usage : input decode base64 data.")
    #     sys.exit(0)

    bytes_value = base64.b64decode(test_data)
    hexs_value = ByteToHex(bytes_value)
    print (hexs_value)