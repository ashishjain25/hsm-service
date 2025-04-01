package com.tmobile.hsmservice.dto;

import java.util.List;

public record KeyDTO(List<PrivateKeyDTO> privatekeys, List<PublicKeyDTO> publickeys, List<AesKeyDTO> aeskeys) {

}
