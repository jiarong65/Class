#include "RsaCrypto.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <iostream>
extern "C"
{
#include <openssl/applink.c>
};

Cryptographic::Cryptographic()
{
	m_privateKey = RSA_new();
	m_publicKey = RSA_new();
}

Cryptographic::Cryptographic(string fileName,bool isPrivate)
{
	m_privateKey = RSA_new();
	m_publicKey = RSA_new();

	if (isPrivate)
	{
		initPrivateKey(fileName);
	}
	else
	{
		initPublicKey(fileName);
	}
}

Cryptographic::~Cryptographic()
{
	RSA_free(m_privateKey);
	RSA_free(m_publicKey);
}

bool Cryptographic::initPrivateKey(string prifile)
{
	BIO* bio = BIO_new_file(prifile.data(), "r");
	if (PEM_read_bio_RSAPrivateKey(bio, &m_privateKey, NULL, NULL) == NULL)
	{
		ERR_print_errors_fp(stdout);
		return false;
	}
	BIO_free(bio);

	return true;
}

bool Cryptographic::initPublicKey(string pubfile)
{
	BIO* bio = BIO_new_file(pubfile.data(), "r");
	if (PEM_read_bio_RSAPublicKey(bio, &m_publicKey, NULL, NULL) == NULL) {
		ERR_print_errors_fp(stdout);
		return false;
	}
	BIO_free(bio);

	return true;
}

void Cryptographic::generateRsaKey(int bits, string pub, string pri)
{
	//1.创建rsa变量
	RSA* rsa = RSA_new();
	//创建bignum对象，初始化
	BIGNUM* e = BN_new();
	BN_set_word(e, 12345);

	//2.生成密钥对
	RSA_generate_key_ex(rsa, 1024, e, NULL);
	//3.将密钥对写入到磁盘
	// 创建bio文件对象
	BIO* pubIO = BIO_new_file(pub.data(), "w");
	// 公钥以pem格式写入到文件中
	PEM_write_bio_RSAPublicKey(pubIO, rsa);
	// 缓存中的数据刷到文件中
	BIO_flush(pubIO);
	BIO_free(pubIO);

	// 创建bio对象
	BIO* priBio = BIO_new_file(pri.data(), "w");
	// 私钥以pem格式写入文件中
	PEM_write_bio_RSAPrivateKey(priBio, rsa, NULL, NULL, 0, NULL, NULL);
	BIO_flush(priBio);
	BIO_free(priBio);

	// 得到公钥
	RSA* pubKey = RSAPublicKey_dup(rsa);
	// 得到私钥
	RSA* priKey = RSAPrivateKey_dup(rsa);

	BN_free(e);
	RSA_free(rsa);
}

string Cryptographic::rsaPubKeyEncrypt(string data)
{
	int keyLen = RSA_size(m_publicKey);
	char* buf = new char[keyLen];
	int ret = RSA_public_encrypt(data.size(), (const unsigned char*)data.data(),
		(unsigned char*)buf, m_publicKey, RSA_PKCS1_PADDING);
	string retStr = string();
	if (ret > 0)
	{
		//加密成功
		retStr = (buf, ret);
	}
	delete[] buf;
	return retStr;
}

string Cryptographic::rsaPriKeyDecrypt(string encData)
{
	int keyLen = RSA_size(m_privateKey);
	char* buf = new char[keyLen];
	int ret = RSA_private_decrypt(encData.size(), (const unsigned char*)encData.data(),
		(unsigned char*)buf, m_privateKey, RSA_PKCS1_PADDING);
	string retStr = string();
	if (ret > 0)
	{
		//解密成功
		retStr = string(buf, ret);
	}
	delete[] buf;
	return retStr;
}

string  Cryptographic::rsaSign(string data, SignLevel level)
{
	unsigned int len;
	char* signBuf = new char[RSA_size(m_privateKey) + 1];
	RSA_sign(level, (const unsigned char*)data.data(), data.size(), (unsigned char*)signBuf,
		&len, m_privateKey);
	cout << "sign len: " << len << endl;
	string retStr = string(signBuf, len);
	delete[]signBuf;
	return retStr;
}

bool Cryptographic::rsaVerify(string data, string signData, SignLevel level)
{
	// 验证签名
	int ret = RSA_verify(level, (const unsigned char*)data.data(), data.size(),
		(const unsigned char*)signData.data(), signData.size(), m_publicKey);
	if (ret != 1)
	{
		return false;
	}
	return true;
}
