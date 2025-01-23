package com.tmobile.hsmservice.dto;

import iaik.pkcs.pkcs11.objects.BooleanAttribute;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.LongAttribute;

public record AesKeyDTO(LongAttribute cka_key_type, CharArrayAttribute cka_label, LongAttribute cka_class,
		BooleanAttribute cka_token, BooleanAttribute cka_private, BooleanAttribute cka_modifiable,
		ByteArrayAttribute cka_id,
		BooleanAttribute cka_derive, BooleanAttribute cka_local) {

}
