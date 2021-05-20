from Cypher_test import *

def main():
    key = b'qwertyuiopasdfghjklzxcvbnm123456'
    key1 = b'qwertyuiopasdfgh'
    test = CryptoTest()
    test.filesGen()
    test.testing(key)

if __name__ == '__main__':
    main()