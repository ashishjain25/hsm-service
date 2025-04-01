package com.tmobile.hsmservice.service;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import io.opentelemetry.api.internal.StringUtils;

@Component
public class HsmServiceUtil {

	private Logger logger = LoggerFactory.getLogger(HsmServiceUtil.class);

	private RSAPrivateKey privateKey;

	private RSAPublicKey publicKey;

	private AESSecretKey aesSecretKey;

	public AESSecretKey getAesSecretKey() {
		return aesSecretKey;
	}

	public void setAesSecretKey(AESSecretKey aesSecretKey) {
		this.aesSecretKey = aesSecretKey;
	}

	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(RSAPrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(RSAPublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * Method to create AES Key
	 * 
	 * @param session: Session object
	 * @param label:   Label of AES key
	 * @return generated and stored AES key
	 */
	public AESSecretKey createAESKey(Session session, char[] label) throws TokenException {

		Mechanism keyMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);

		AESSecretKey secretKeyTemplate = new AESSecretKey();

		secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
		//secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
		//secretKeyTemplate.getModifiable().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
		//secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
		//secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
		secretKeyTemplate.getLabel().setCharArrayValue(label);
		secretKeyTemplate.getValueLen().setLongValue(32L);

		setAesSecretKey(secretKeyTemplate);

		AESSecretKey generatedSecretKey = (AESSecretKey) session.generateKey(keyMechanism, secretKeyTemplate);
		return generatedSecretKey;

	}

	/**
	 * Method to generate RSA key pair.
	 *
	 * @param privateKeyTemplate : Template of the generated private key
	 * @param publicKeyTemplate  : Template of the generated private key
	 * @return KeyPair if pair of keys generated, else null.
	 * @throws TokenException : returns if exception occurred in the Token.
	 */
	public KeyPair generateRSAKeyPair(Session session, String label) throws TokenException {

		Mechanism keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
		MechanismInfo mechanismInfo = session.getToken().getMechanismInfo(keyPairGenerationMechanism);

		RSAPublicKey publicKeyTemplate = new RSAPublicKey();
		RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();

		if ((keyPairGenerationMechanism != null) && (mechanismInfo != null)) {

			privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
			privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
			privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
			privateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
			privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
			privateKeyTemplate.getLabel().setCharArrayValue((label).toCharArray());

			byte[] publicExponentBytes = { 0x01, 0x00, 0x00, 0x00, 0x01 };

			publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
			publicKeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);
			publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
			publicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
			publicKeyTemplate.getLabel().setCharArrayValue((label).toCharArray());
			publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
			publicKeyTemplate.getModulusBits().setLongValue(2048l);

			setPrivateKey(privateKeyTemplate);
			setPublicKey(publicKeyTemplate);

			return session.generateKeyPair(keyPairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);

		}
		return null;

	}

	public List<PrivateKey> getPrivateKeys(Session session) throws TokenException {
		// find private RSA keys that the application can use for signing - START HERE
		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

		session.findObjectsInit(privateSignatureKeyTemplate);
		Object[] privateSignatureKeys;

		List<PrivateKey> signatureKeyList = new ArrayList<>();
		while ((privateSignatureKeys = session.findObjects(1)).length > 0) {
			// logger.info("private key: {}", privateSignatureKeys[0]);
			if (privateSignatureKeys[0] instanceof PrivateKey) {
				// logger.info("Adding private key object to list");
				signatureKeyList.add((PrivateKey) privateSignatureKeys[0]);
			}
		}

		session.findObjectsFinal();
		return signatureKeyList;
	}

	public PublicKey getPublicKey(Session session, String label) throws TokenException {
		// find public RSA keys that the application can use for signing - START HERE
		RSAPublicKey publicSignatureKeyTemplate = new RSAPublicKey();
		session.findObjectsInit(publicSignatureKeyTemplate);

		Object[] publicSignatureKeys;
		PublicKey key = null;
		while ((publicSignatureKeys = session.findObjects(1)).length > 0) {
			if (publicSignatureKeys[0] instanceof PublicKey) {
				key = (PublicKey) publicSignatureKeys[0];
			//	logger.info("key label :{}", key.getLabel());
				
				if (key.getLabel() != null && key.getLabel().getCharArrayValue() != null
						&& String.valueOf(key.getLabel().getCharArrayValue()).equals(label)) {
					break;
				}
			}
		}

		session.findObjectsFinal();
		return key;

	}
	
	public PrivateKey getPrivateKey(Session session, String label) throws TokenException {
		// find private RSA keys that the application can use for signing - START HERE
		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		session.findObjectsInit(privateSignatureKeyTemplate);

		Object[] publicSignatureKeys;
		PrivateKey key = null;
		while ((publicSignatureKeys = session.findObjects(1)).length > 0) {
			if (publicSignatureKeys[0] instanceof PrivateKey) {
				key = (PrivateKey) publicSignatureKeys[0];
			//	logger.info("key label :{}", key.getLabel());
				
				if (key.getLabel() != null && key.getLabel().getCharArrayValue() != null
						&& String.valueOf(key.getLabel().getCharArrayValue()).equals(label)) {
					break;
				}
			}
		}

		session.findObjectsFinal();
		return key;

	}

	public List<PublicKey> getPublicKeys(Session session) throws TokenException {
		// find public RSA keys that the application can use for signing - START HERE
		RSAPublicKey publicSignatureKeyTemplate = new RSAPublicKey();

		session.findObjectsInit(publicSignatureKeyTemplate);
		Object[] publicSignatureKeys;

		List<PublicKey> signatureKeyList = new ArrayList<>();
		while ((publicSignatureKeys = session.findObjects(1)).length > 0) {
			// logger.info("public key: {}", publicSignatureKeys[0]);
			if (publicSignatureKeys[0] instanceof PublicKey) {
				// logger.info("Adding public key object to list");
				signatureKeyList.add((PublicKey) publicSignatureKeys[0]);
			}
		}

		session.findObjectsFinal();
		return signatureKeyList;
	}

	public List<AESSecretKey> getAESKeys(Session session) throws TokenException {
		// find public RSA keys that the application can use for signing - START HERE
		AESSecretKey aesSignatureKeyTemplate = new AESSecretKey();

		session.findObjectsInit(aesSignatureKeyTemplate);
		Object[] aesSignatureKeys;

		List<AESSecretKey> signatureKeyList = new ArrayList<>();
		while ((aesSignatureKeys = session.findObjects(1)).length > 0) {
			// logger.info("aes key: {}", aesSignatureKeys[0]);
			if (aesSignatureKeys[0] instanceof AESSecretKey) {
				// logger.info("Adding AES key object to list");
				signatureKeyList.add((AESSecretKey) aesSignatureKeys[0]);
			}
		}

		session.findObjectsFinal();
		return signatureKeyList;
	}

}
