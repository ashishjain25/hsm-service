package com.tmobile.hsmservice.dto;

import org.springframework.stereotype.Component;

import com.tmobile.hsmservice.dto.RSAKeyPairDTO.PrivateKeyDTO;
import com.tmobile.hsmservice.dto.RSAKeyPairDTO.PublicKeyDTO;

import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.KeyPair;

@Component
public class HsmDTOUtil {

	public AesKeyDTO createAesKeyDTO(AESSecretKey aesSecretKey) {
		return new AesKeyDTO(aesSecretKey.getKeyType(), aesSecretKey.getLabel(), aesSecretKey.getObjectClass(),
				aesSecretKey.getToken(), aesSecretKey.getPrivate(), aesSecretKey.getModifiable(), aesSecretKey.getId(),
				aesSecretKey.getDerive(), aesSecretKey.getLocal());
	}

	public RSAKeyPairDTO createRsaKeyPairDTO(KeyPair keypair) {
		return new RSAKeyPairDTO(
				new PrivateKeyDTO(keypair.getPrivateKey().getId(), keypair.getPrivateKey().getLabel(),
						keypair.getPrivateKey().getKeyType()),
				new PublicKeyDTO(keypair.getPrivateKey().getId(), keypair.getPrivateKey().getLabel(),
						keypair.getPrivateKey().getKeyType()));
	}
}
