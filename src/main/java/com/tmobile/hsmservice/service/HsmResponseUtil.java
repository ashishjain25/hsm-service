package com.tmobile.hsmservice.service;

import org.springframework.stereotype.Component;

import com.tmobile.hsmservice.dto.AesKeyDTO;
import com.tmobile.hsmservice.dto.RSAKeyPairDTO;

import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;

@Component
public class HsmResponseUtil {

	public AesKeyDTO createAesKeyDTO(AESSecretKey aesSecretKey) {
		return new AesKeyDTO(aesSecretKey.getLabel().getCharArrayValue());
	}

	public RSAKeyPairDTO createRsaKeyPairDTO(KeyPair keypair) {
		return new RSAKeyPairDTO(keypair.getPrivateKey().getLabel().getCharArrayValue(),
				keypair.getPublicKey().getLabel().getCharArrayValue(),
				keypair.getPublicKey().getKeyGenMechanism().getMechanism().getName());
	}

	public RSAKeyPairDTO createRsaKeyPairDTO(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
		return new RSAKeyPairDTO(privateKey.getLabel().getCharArrayValue(), publicKey.getLabel().getCharArrayValue(),
				publicKey.getKeyGenMechanism().getMechanism().getName());
	}
}
