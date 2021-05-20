import os
import os
import os.path
import time
from typing import List

import matplotlib.pyplot as plt

from Ciphers import *


class CryptoTest:

    file_names = ('file_512kb', 'file_1mb', 'file_2mb', 'file_4mb')
    file_sizes = (524288, 1048576, 2097152, 4194304)
    cipher_encryption_time = []
    cipher_decryption_time = []

    def filesGen(self):
        if len(self.file_names) != len(self.file_sizes):
            raise Exception('lists sizes not equal')
        else:
            if not os.path.isdir('images'):
                os.mkdir('images')
            if not os.path.isdir('files'):
                os.mkdir('files')
            for i in range(len(self.file_names)):
                file_name = self.file_names[i]
                print('Creation {}'.format(file_name))
                with open('files/{}'.format(file_name), 'wb') as f:
                    f.write(os.urandom(self.file_sizes[i]))
                    print('{} created'.format(file_name))

    def local_plot(self, cipher, enc_time, dec_time):
        fig, ax = plt.subplots()
        plt.title(cipher)
        plt.xlabel("File size")
        plt.ylabel("Microseconds")
        plt.grid()
        ax.plot(self.file_names, enc_time, label='Encription')
        ax.plot(self.file_names, dec_time, label='Decription')
        ax.legend()
        image_name = 'images/' + cipher + '.png'
        plt.savefig(image_name, dpi=100)
        plt.show()

    def common_plot(self, algorithms):
        ig, ax = plt.subplots()
        plt.title("Common result encryption")
        plt.xlabel("File size")
        plt.ylabel("Microseconds")
        plt.grid()
        for i in range(len(algorithms)):
            ax.plot(self.file_names, self.cipher_encryption_time[i], label=algorithms[i].cyp_name())
        ax.legend()
        plt.savefig('images/result_enc.png')
        plt.show()
        fig, ax = plt.subplots()
        plt.title("Common result decryption")
        plt.xlabel("File size")
        plt.ylabel("Microseconds")
        plt.grid()
        for i in range(len(algorithms)):
            ax.plot(self.file_names, self.cipher_decryption_time[i], label=algorithms[i].cyp_name())
        ax.legend()
        plt.savefig('images/result_dec.png')
        plt.show()

    def testing(self, key):
        alghoritms: List[Abstract_cypher] = []

        empty = NoEncrypt()
        #alghoritms.append(CAMELLIA_cipher(empty))
        alghoritms.append(AES_cypher(empty))
        alghoritms.append(SERPENT_cypher(empty))
        #alghoritms.append(TWOFISH_cipher(empty))
        #alghoritms.append(KUZNECHIK_cipher(empty))
        #alghoritms.append(AES_cypher(TWOFISH_cipher(empty)))
        #alghoritms.append(AES_cypher(TWOFISH_cipher(SERPENT_cypher(empty))))
        #alghoritms.append(CAMELLIA_cipher(KUZNECHIK_cipher(empty)))
        #alghoritms.append(CAMELLIA_cipher(SERPENT_cypher(empty)))
        #alghoritms.append(KUZNECHIK_cipher(AES_cypher(empty)))
        #alghoritms.append(KUZNECHIK_cipher(SERPENT_cypher(CAMELLIA_cipher(empty))))
        #alghoritms.append(KUZNECHIK_cipher(TWOFISH_cipher(empty)))
        #alghoritms.append(SERPENT_cypher(AES_cypher(empty)))
        #alghoritms.append(SERPENT_cypher(TWOFISH_cipher(AES_cypher(empty))))
        #alghoritms.append(TWOFISH_cipher(SERPENT_cypher(empty)))

        for algorithm in alghoritms:
            print(" " + algorithm.cyp_name())
            encryption_time = []
            decryption_time = []
            for filename in self.file_names:
                with open('files/' + filename, 'rb') as f:
                    data = f.read()
                    print("File {}".format(filename))
                start_time = time.time()
                encrypted = algorithm.encrypt(data, key)
                end_time = time.time()
                res_time = (end_time - start_time)
                print("     Time encrypt:{}".format(res_time))
                encryption_time.append(res_time)

                start_time = time.time()
                decrypted = algorithm.decrypt(encrypted, key)
                end_time = time.time()
                res_time = (end_time - start_time)
                print("     Time decrypt:{}".format(res_time))
                decryption_time.append(res_time)

            self.local_plot(algorithm.cyp_name(), encryption_time, decryption_time)
            self.cipher_encryption_time.append(encryption_time)
            self.cipher_decryption_time.append(decryption_time)
        self.common_plot(alghoritms)
