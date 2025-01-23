package com.tmobile.hsmservice.dto;

import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.LongAttribute;

public record RSAKeyPairDTO(PrivateKeyDTO privatekeydto, PublicKeyDTO publicKeyDTO) {
	
	record PrivateKeyDTO(ByteArrayAttribute id, CharArrayAttribute label, LongAttribute keytype) {}
	
	record PublicKeyDTO(ByteArrayAttribute id, CharArrayAttribute label, LongAttribute keytype) {}

}
