package com.tmobile.hsmservice.validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class AlgorithmValidator implements ConstraintValidator<ValidAlgorithm, String> {
	private Logger logger = LoggerFactory.getLogger(AlgorithmValidator.class);
	
	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		try {
			CryptoKeyVersionAlgorithm.valueOf(value);
			return true;
		} catch (IllegalArgumentException e) {
			logger.info("Algorithm {} defined is invalid",value);
			return false;
		}

	}

}
