import argparse
import sys
import time

number_char_decode_dict = "0123456789"
lower_char_decode_dict = "abcdefghijklmnopqrstuvwxyz"
upper_char_decode_dict = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

number_char_encode_dict = ""
lower_char_encode_dict = ""
upper_char_encode_dict = ""

def set_encode_dict(number_move, lower_move, upper_move):
    global number_char_encode_dict
    global lower_char_encode_dict
    global upper_char_encode_dict
    
    number_char_encode_dict = ""
    for i,j in enumerate(number_char_decode_dict):
        number_char_encode_dict += chr((ord(j) - 48 + number_move) % 10 + 48)
    
    lower_char_encode_dict = ""
    for i,j in enumerate(lower_char_decode_dict):
        lower_char_encode_dict += chr((ord(j) - 97 + lower_move) % 26 + 97 )
    
    upper_char_encode_dict = ""
    for i,j in enumerate(upper_char_decode_dict):
        upper_char_encode_dict += chr((ord(j) - 65 + upper_move) % 26 + 65)

def caesar_encode(cipher_text):
    decode_result = ""
    
    for i,j in enumerate(cipher_text):
        if j in number_char_encode_dict:
            idx = number_char_encode_dict.find(j)
            decode_result += number_char_decode_dict[idx]
        elif j in lower_char_encode_dict:
            idx = lower_char_encode_dict.find(j)
            decode_result += lower_char_decode_dict[idx]
        elif j in upper_char_encode_dict:
            idx = upper_char_encode_dict.find(j)
            decode_result += upper_char_decode_dict[idx]
        else:
            decode_result += j
            
    print (decode_result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cipher_text', default=None)
    parser.add_argument('-d', '--default', default=None)
    parser.add_argument("-n", '--number', default=None)
    parser.add_argument("-u", '--upper', default=None)
    parser.add_argument("-l", '--lower', default=None)
    args = parser.parse_args()
    
    if (args.default == None) and (args.number == None) and (args.upper == None) and (args.lower == None):
        print ("Not Find Parameter.")
        sys.exit(0)
        
    if args.cipher_text == None:
        print ("Not Find Parameter.")
        sys.exit(0)
        
    if args.default != None:
        number_move = int(args.default)
        upper_move = int(args.default)
        lower_move = int(args.default)
    else:
        if args.number != None:
            number_move = int(args.number)
        else:
            number_move = 0
            
        if args.upper != None:
            upper_move = int(args.upper)
        else:
            upper_move = 0
            
        if args.lower != None:
            lower_move = int(args.lower)
        else:
            lower_move = 0
    
    if (number_move == 0) and (upper_move == 0) and (lower_move == 0):
        for i in range(1, 26):
            print ("offset : " + str(i))
            set_encode_dict(i, i, i)
            caesar_encode(args.cipher_text)
            time.sleep(1)
    else:
        set_encode_dict(number_move, lower_move, upper_move)
        caesar_encode(args.cipher_text)