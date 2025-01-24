package com.tmobile.hsmservice.dto;

import java.util.Map;

import com.tmobile.hsmservice.validator.ValidAlgorithm;
import com.tmobile.hsmservice.validator.ValidPurpose;

import jakarta.validation.constraints.NotNull;

public record CryptoKeyDTO(@NotNull(message = "Please provide a valid crypto key id") String name,
		@ValidPurpose String purpose, @ValidAlgorithm String alogirthm, Map<String, String> labels) {
}
