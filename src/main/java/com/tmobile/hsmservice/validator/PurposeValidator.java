package com.tmobile.hsmservice.validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.cloud.kms.v1.CryptoKey.CryptoKeyPurpose;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PurposeValidator implements ConstraintValidator<ValidPurpose, String> {

	private Logger logger = LoggerFactory.getLogger(PurposeValidator.class);
	
	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		try {
			CryptoKeyPurpose.valueOf(value);
			return true;
		} catch (IllegalArgumentException e) {
			// Handle invalid purpose gracefully
			logger.info("Purpose {} defined is invalid",value);
			return false;
		}

	}

}
