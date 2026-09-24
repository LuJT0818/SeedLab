#include <iostream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>

using namespace std;

/*
EVP_CIPHER_CTX_new()：创建上下文。
EVP_EncryptInit_ex()：初始化，指定算法（如 EVP_aes_128_cbc()）、密钥和 IV。
EVP_EncryptUpdate()：传入明文，获取密文。
EVP_EncryptFinal_ex()：处理最后的填充块。
EVP_CIPHER_CTX_free()：释放上下文。
*/

bool aes_decrypt_128_cbc(const vector <unsigned char>& ciphertext,
                                   const vector <unsigned char> &key,
                                   const vector <unsigned char> &iv,
                                   vector <unsigned char> &out_plaintext){
    
    /*
    创建上下文
    EVP_CIPHER和EVP_CIPHER_CTX是EVP加密算法的两个基本结构体，分别用于表示加密算法信息和维护加密过程的上下文
    其中前者是后者的成员之一
    */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    /*
    初始化上下文
    将参数列表中的加密算法类型、密钥、初始向量保存在上下文ctx中
    */ 
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data());

    vector <unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;
    /*
    解密
    取ciphertext.data()中指定尺寸(ciphertext.size())的数据
    将其解密并保存在plaintext.data()中, 实际解密后的数据的长度保存在len中
    (不会处理最后的填充块)
    */
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;

    /*
    处理最后的填充块
    将剩余的填充块解密并保存在plaintext.data()中, 实际解密后的数据的长度保存在len中
    */
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    
    
    plaintext.resize(plaintext_len);
    out_plaintext = move(plaintext);
    //释放上下文
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

vector <unsigned char> hex_to_bytes(const string& hex){
    vector <unsigned char> out;
    out.reserve(hex.size() / 2); 
    auto nibble = [](char c) -> int{ 
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2){
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        out.push_back(hi * 16 + lo);
    }
    return out;
}
bool make_key(const string &word, vector <unsigned char> &key){
    key.assign(word.begin(), word.end());
    key.resize(16, static_cast<unsigned char>('#'));
    return true;
}

int main(){
    string known_plaintext = "This is a top secret.";
    string ciphertext_hex = "764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2";
    string iv_hex = "aabbccddeeff00998877665544332211";

    vector <unsigned char> ciphertext = hex_to_bytes(ciphertext_hex);
    vector <unsigned char> iv = hex_to_bytes(iv_hex);

    string dict_path = "Labsetup/Files/words.txt";
    ifstream dict(dict_path);

    string word;
    int cnt = 0;
    while(getline(dict, word)){
        cnt++;
        while(!word.empty() && (word.back() == '\r' || word.back() == '\n' ||
                                 word.back() == ' '  || word.back() == '\t')){ 
            word.pop_back();            
        }
    
        vector <unsigned char> key;
        make_key(word, key);
        vector <unsigned char> plaintext;
        if(aes_decrypt_128_cbc(ciphertext, key, iv, plaintext)){ 
            string pt(plaintext.begin(), plaintext.end());
            // 解密结果含 PKCS#7 填充，只比较前 strlen(known_plaintext) 个字节
            if (pt.size() >= known_plaintext.size() &&
                pt.compare(0, known_plaintext.size(), known_plaintext) == 0){
                cout << cnt << ": Found key: " << word << endl;
                return 0;
            }
        }
    }
    cout << cnt << ": Key not found" << endl;
    return 0;
    // change again
}