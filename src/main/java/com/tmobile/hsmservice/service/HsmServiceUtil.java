package com.tmobile.hsmservice.service;

import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

@Component
public class HsmServiceUtil {

	private Logger logger = LoggerFactory.getLogger(HsmService.class);

	/**
	 * Method to create AES Key
	 * 
	 * @param session: Session object
	 * @param label:   Label of AES key
	 * @return generated and stored AES key
	 */
	public AESSecretKey createAESKey(Session session, char[] label) {

		Mechanism keyMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);

		AESSecretKey secretKeyTemplate = new AESSecretKey();
		logger.info("****************AES key attributes {}", secretKeyTemplate.getSetAttributes());
		secretKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);

		secretKeyTemplate.getLabel().setCharArrayValue(label);
		secretKeyTemplate.getValueLen().setLongValue(32l);

		secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getUnwrapTemplate().setPresent(false);

		logger.info("AES key attributes {}", secretKeyTemplate.getSetAttributes());
		try {
			AESSecretKey generatedSecretKey = (AESSecretKey) session.generateKey(keyMechanism, secretKeyTemplate);
			return generatedSecretKey;
		} catch (TokenException e) {
			System.out.println("AES key generation error: " + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Method to generate RSA key pair.
	 *
	 * @param privateKeyTemplate : Template of the generated private key
	 * @param publicKeyTemplate  : Template of the generated private key
	 * @return KeyPair if pair of keys generated, else null.
	 * @throws TokenException : returns if exception occurred in the Token.
	 */
	public KeyPair generateRSAKeyPair(Session session, RSAPrivateKey privateKeyTemplate, RSAPublicKey publicKeyTemplate,
			String imei) throws TokenException {

		MechanismInfo mechanismInfo = null;
		Mechanism keyPairGenerationMechanism = null;

		mechanismInfo = session.getToken().getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN));
		keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);

		if ((keyPairGenerationMechanism != null) && (mechanismInfo != null)) {

			privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
			privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
			privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

			publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);

			publicKeyTemplate.getVerify().setBooleanValue(mechanismInfo.isVerify());
			publicKeyTemplate.getVerifyRecover().setBooleanValue(mechanismInfo.isVerifyRecover());
			publicKeyTemplate.getEncrypt().setBooleanValue(mechanismInfo.isEncrypt());
			publicKeyTemplate.getDerive().setBooleanValue(mechanismInfo.isDerive());
			publicKeyTemplate.getId().setByteArrayValue((imei + "PublicKey").getBytes());
			publicKeyTemplate.getLabel().setCharArrayValue((imei + "PublicKey").toCharArray());
			publicKeyTemplate.getKeyGenMechanism().setMechanism(keyPairGenerationMechanism);
			// publicKeyTemplate.getSubject().setByteArrayValue((imei+"subject").getBytes());

			Calendar cal = Calendar.getInstance();
			Date today = cal.getTime();
			cal.add(Calendar.YEAR, 1);
			Date nextYear = cal.getTime();

			Calendar.getInstance().add(Calendar.YEAR, 1);
			publicKeyTemplate.getStartDate().setDateValue(today);
			publicKeyTemplate.getEndDate().setDateValue(nextYear);
			publicKeyTemplate.getSubject().setPresent(false);
			// publicKeyTemplate.removeAttribute(PKCS11Constants.CKA_WRAP_TEMPLATE);
			// publicKeyTemplate.getWrapTemplate().setValue(publicKeyTemplate);
			// publicKeyTemplate.getAllowedMechanisms().setValue(keyPairGenerationMechanism);
			// privateKeyTemplate.removeAttribute(PKCS11Constants.CKR_DEVICE_ERROR);
			// publicKeyTemplate.removeAttribute(PKCS11Constants.CKA_ALLOWED_MECHANISMS);
			// publicKeyTemplate.getWrapTemplate().isPresent();
			// publicKeyTemplate.getAllowedMechanisms().isPresent();

			//logger.info("Public key attributes {}", publicKeyTemplate.getSetAttributes());

			/*
			 * publicKeyTemplate.getWrap() .setBooleanValue(mechanismInfo.isUnwrap());
			 */

			privateKeyTemplate.getSign().setBooleanValue(mechanismInfo.isSign());
			privateKeyTemplate.getSignRecover().setBooleanValue(mechanismInfo.isSignRecover());
			privateKeyTemplate.getDecrypt().setBooleanValue(mechanismInfo.isDecrypt());
			privateKeyTemplate.getDerive().setBooleanValue(mechanismInfo.isDerive());
			privateKeyTemplate.getId().setByteArrayValue((imei + "PrivateKey").getBytes());
			privateKeyTemplate.getLabel().setCharArrayValue((imei + "PrivateKey").toCharArray());
			privateKeyTemplate.getKeyGenMechanism().setMechanism(keyPairGenerationMechanism);
			privateKeyTemplate.getStartDate().setDateValue(today);
			privateKeyTemplate.getEndDate().setDateValue(nextYear);
			// privateKeyTemplate.getSubject().setByteArrayValue((imei+"subject").getBytes());
			// privateKeyTemplate.removeAttribute(PKCS11Constants.CKA_WRAP_TEMPLATE);
			// privateKeyTemplate.removeAttribute(PKCS11Constants.CKR_DEVICE_ERROR);
			// privateKeyTemplate.removeAttribute(PKCS11Constants.CKA_ALLOWED_MECHANISMS);
			// privateKeyTemplate.getAllowedMechanisms().isPresent();
			// privateKeyTemplate.getWrapWithTrusted().isPresent();

			//logger.info("Private key attributes {}", privateKeyTemplate.getSetAttributes());
			/*
			 * privateKeyTemplate.getUnwrap() .setBooleanValue(mechanismInfo.isUnwrap());
			 */

			return session.generateKeyPair(keyPairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);

			/*
			 * session.findObjectsInit(publicKeyTemplate);
			 * logger.info("object length {} ",session.findObjects(5).length); Object[]
			 * privateSignatureKeys; List signatureKeyList = new Vector(4); while
			 * ((privateSignatureKeys = session.findObjects(1)).length > 0) {
			 * logger.info("private key: {}", privateSignatureKeys[0]);
			 * signatureKeyList.add(privateSignatureKeys[0]); }
			 */
		}
		return null;

	}

}
