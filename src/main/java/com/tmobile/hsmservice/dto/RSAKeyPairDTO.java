package com.tmobile.hsmservice.dto;

public record RSAKeyPairDTO(char[] privatekeylabel, char[] publickeylabel, String keygenerationmechanism) {
}
