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
	//1.����rsa����
	RSA* rsa = RSA_new();
	//����bignum���󣬳�ʼ��
	BIGNUM* e = BN_new();
	BN_set_word(e, 12345);

	//2.������Կ��
	RSA_generate_key_ex(rsa, 1024, e, NULL);
	//3.����Կ��д�뵽����
	// ����bio�ļ�����
	BIO* pubIO = BIO_new_file(pub.data(), "w");
	// ��Կ��pem��ʽд�뵽�ļ���
	PEM_write_bio_RSAPublicKey(pubIO, rsa);
	// �����е�����ˢ���ļ���
	BIO_flush(pubIO);
	BIO_free(pubIO);

	// ����bio����
	BIO* priBio = BIO_new_file(pri.data(), "w");
	// ˽Կ��pem��ʽд���ļ���
	PEM_write_bio_RSAPrivateKey(priBio, rsa, NULL, NULL, 0, NULL, NULL);
	BIO_flush(priBio);
	BIO_free(priBio);

	// �õ���Կ
	RSA* pubKey = RSAPublicKey_dup(rsa);
	// �õ�˽Կ
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
		//���ܳɹ�
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
		//���ܳɹ�
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
	// ��֤ǩ��
	int ret = RSA_verify(level, (const unsigned char*)data.data(), data.size(),
		(const unsigned char*)signData.data(), signData.size(), m_publicKey);
	if (ret != 1)
	{
		return false;
	}
	return true;
}
