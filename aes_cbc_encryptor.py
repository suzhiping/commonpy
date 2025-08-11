import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES-256 要求密钥长度为 32 字节
KEY_SIZE = 32
# AES 的块大小固定为 16 字节 (也是IV的长度)
BLOCK_SIZE = 16


def get_key_from_password(password: str) -> bytes:
    """从用户提供的字符串密码生成一个32字节的AES密钥。"""
    return hashlib.sha256(password.encode('utf-8')).digest()


def encrypt_file(password: str, plaintext_path: str, ciphertext_path: str):
    """
    使用AES-CBC模式和随机IV加密文件，并将IV存储在密文头部。
    """
    try:
        key = get_key_from_password(password)

        # 1. 生成一个密码学安全的随机IV
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        with open(plaintext_path, 'rb') as f_in, open(ciphertext_path, 'wb') as f_out:
            # 2. 【关键】将IV写入输出文件的开头，这是移植性的保证
            f_out.write(iv)

            # 3. 加密明文并写入IV之后
            while True:
                chunk = f_in.read(1024 * BLOCK_SIZE)
                if len(chunk) == 0:
                    break
                # PKCS7填充只在最后一个块需要
                if len(chunk) % BLOCK_SIZE != 0:
                    chunk = pad(chunk, BLOCK_SIZE)

                encrypted_chunk = cipher.encrypt(chunk)
                f_out.write(encrypted_chunk)

        print(f"✅ 文件 '{plaintext_path}' 已成功加密到 '{ciphertext_path}' (使用随机IV)")

    except FileNotFoundError:
        print(f"❌ 错误: 文件 '{plaintext_path}' 未找到。")
    except Exception as e:
        print(f"❌ 加密过程中发生错误: {e}")


def decrypt_file(password: str, ciphertext_path: str, decrypted_path: str):
    """
    解密文件。首先从文件头部读取IV，然后用其解密剩余数据。
    """
    try:
        key = get_key_from_password(password)

        with open(ciphertext_path, 'rb') as f_in:
            # 1. 【关键】从文件开头读取16字节的IV
            iv = f_in.read(BLOCK_SIZE)
            if len(iv) < BLOCK_SIZE:
                raise ValueError("密文文件不完整或格式错误，无法读取IV。")

            cipher = AES.new(key, AES.MODE_CBC, iv)

            with open(decrypted_path, 'wb') as f_out:
                # 2. 解密IV之后的所有数据
                while True:
                    chunk = f_in.read(1024 * BLOCK_SIZE)
                    if len(chunk) == 0:
                        break
                    decrypted_chunk = cipher.decrypt(chunk)
                    f_out.write(decrypted_chunk)

        # 3. 解密完成后，需要对整个解密后的文件内容进行一次性的unpad处理
        # 这是一个稍微复杂点的地方，简单起见我们先读回整个文件再处理
        with open(decrypted_path, 'rb+') as f:
            decrypted_data = f.read()
            try:
                unpadded_data = unpad(decrypted_data, BLOCK_SIZE)
                f.seek(0)
                f.truncate()
                f.write(unpadded_data)
                print(f"✅ 文件 '{ciphertext_path}' 已成功解密到 '{decrypted_path}'")
            except ValueError:
                # 如果密码错误，unpad会失败
                print("❌ 解密失败！密码错误或文件已损坏。")
                f.close()  # 关闭文件句柄
                os.remove(decrypted_path)  # 删除错误的解密文件

    except FileNotFoundError:
        print(f"❌ 错误: 文件 '{ciphertext_path}' 未找到。")
    except Exception as e:
        print(f"❌ 解密过程中发生错误: {e}")



import unittest
class TestAesDbc(unittest.TestCase):
    def setUp(self):
        self.base_dir = r'/'
        self.plain_filename = f'{self.base_dir}aa.txt'
        self.cliper_filename = f'{self.base_dir}bb.txt'
        self.py_decrypto_filename = f'{self.base_dir}cc-ee.txt'
        self.py_decrpyto_from_node = f'{self.
        base_dir}py_decrpyto_from_node.txt'
        self.js_cliper_filename = f'{self.base_dir}js_out_decrypto.bin'
        self.default_password = '12344'
    def testPyEeCrypto(self):
        encrypt_file(self.default_password,self.plain_filename,self.cliper_filename)

    def testPyDecrpto(self):
        decrypt_file(self.default_password,self.cliper_filename,self.py_decrypto_filename)

    def testPyDecrptoForNode(self):
        node_password = 'jspasword11'
        decrypt_file(node_password,f'{self.base_dir}js_out_decrypto.bin',f'{self.base_dir}py_decrypto_from_node.txt')

if __name__ == '__main__':
    base_dir = f'/'
    orgin_file = 'a.txt'
    cliper_file_name = 'd_out_file.bin'
    decrypto_file_name = 'py_o_out.txt'
    password = '111'
    test_encrypto = False
    if test_encrypto:
        encrypt_file(password, base_dir + orgin_file, base_dir + cliper_file_name)
    else:
        decrypt_file(password , base_dir + cliper_file_name, base_dir + decrypto_file_name)
