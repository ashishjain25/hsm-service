package com.tmobile.hsmservice.validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.cloud.kms.v1.ProtectionLevel;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ProtectionLevelValidator implements ConstraintValidator<ValidAlgorithm, String> {

	private Logger logger = LoggerFactory.getLogger(ProtectionLevelValidator.class);

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		try {
			ProtectionLevel.valueOf(value);
			return true;
		} catch (IllegalArgumentException e) {
			logger.info("Protection level {} defined is invalid", value);
			return false;
		}
	}

}
