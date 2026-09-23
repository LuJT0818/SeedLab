#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEED Lab -- Encryption Oracle (known_iv / 端口 3000)

目标：在不知道 AES 密钥的前提下，判断 Bob 的密文对应的明文是 "Yes" 还是 "No"。

原理（CBC 第一块）：
        C1 = E_k( P1 XOR IV )
    Bob :  CB = E_k( PB XOR IVB )          PB 是 "Yes" 或 "No"（PKCS#7 填充后 16 字节）
    我们:  CA = E_k( PA XOR IVA )          IVA 由预言机每轮公布，PA 由我们任选
只要令  PA = PB XOR IVB XOR IVA，就有 CA == CB。
PB 只有两个候选，因此最多两次查询即可判定。

用法:
    python3 oracle_attack.py [host] [port]     # 默认 10.9.0.80 3000
"""
import re
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.9.0.80"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3000

BLOCK = 16
PROMPT = b"Your plaintext :"
CANDIDATES = ("Yes", "No")


def pkcs7(data: bytes, block: int = BLOCK) -> bytes:
    """PKCS#7 填充，与服务端 EVP_EncryptFinal_ex 的行为一致。"""
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def grab_hex(data: bytes, label: bytes):
    m = re.search(label + rb"\s*:\s*([0-9a-fA-F]+)", data)
    return m.group(1).decode() if m else None


def last_next_iv(data: bytes):
    ivs = re.findall(rb"Next IV\s*:\s*([0-9a-fA-F]+)", data)
    return ivs[-1].decode() if ivs else None


class Oracle:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.buf = b""

    def read_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(marker)
        if idx < 0:                      # 连接关闭
            out, self.buf = self.buf, b""
            return out
        end = idx + len(marker)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def encrypt(self, plaintext: bytes) -> bytes:
        """发送一个明文，返回服务端回显的 'Your ciphertext' 所在的那一段输出。"""
        self.sock.sendall(plaintext.hex().encode() + b"\n")
        return self.read_until(PROMPT)

    def close(self):
        self.sock.close()


def main():
    oracle = Oracle(HOST, PORT)
    try:
        # 第 1 轮输出里同时包含 Bob 的密文、Bob 的 IV，以及第一个 "Next IV"
        chunk = oracle.read_until(PROMPT)
        bob_ct_hex = grab_hex(chunk, b"Bob's ciphertex")
        bob_iv_hex = grab_hex(chunk, b"The IV used")
        next_iv_hex = last_next_iv(chunk)

        if not (bob_ct_hex and bob_iv_hex and next_iv_hex):
            print("[!] 没能解析服务端输出:\n", chunk.decode(errors="replace"))
            return 1

        bob_ct = bytes.fromhex(bob_ct_hex)
        bob_iv = bytes.fromhex(bob_iv_hex)
        next_iv = bytes.fromhex(next_iv_hex)

        print("[*] Bob's ciphertext :", bob_ct_hex)
        print("[*] Bob's IV         :", bob_iv_hex)
        print("[*] Next IV (round 1):", next_iv_hex)
        print()

        answer = None
        for cand in CANDIDATES:
            # PA = pad(cand) XOR IVB XOR IVA
            crafted = xor(pkcs7(cand.encode()), xor(bob_iv, next_iv))
            print(f"[*] 尝试明文 {cand!r}  -> 提交 PA = {crafted.hex()}")

            resp = oracle.encrypt(crafted)
            our_ct_hex = grab_hex(resp, b"Your ciphertext")
            if our_ct_hex is None:
                print("[!] 服务端没有返回密文:\n", resp.decode(errors="replace"))
                return 1
            our_ct = bytes.fromhex(our_ct_hex)
            print(f"    我们的密文      = {our_ct_hex}")

            # 只比较第一块（我们的明文恰好 16 字节，PKCS#7 会再补一整块）
            if our_ct[:BLOCK] == bob_ct[:BLOCK]:
                print(f"    ==> 第一块与 Bob 的密文完全相同!  Bob 的明文是 {cand!r}")
                answer = cand
                break

            print("    ==> 不匹配，换下一个候选\n")
            next_iv_hex = last_next_iv(resp)
            if next_iv_hex is None:
                print("[!] 拿不到下一轮的 IV")
                return 1
            next_iv = bytes.fromhex(next_iv_hex)
            print("[*] Next IV (next round):", next_iv_hex, "\n")

        print()
        if answer:
            print(f"[+] 结论: Bob 的明文是 \"{answer}\"")
        else:
            print("[-] 两个候选都不匹配（理论上不应该发生）")
            return 1
        return 0
    finally:
        oracle.close()


if __name__ == "__main__":
    sys.exit(main())
