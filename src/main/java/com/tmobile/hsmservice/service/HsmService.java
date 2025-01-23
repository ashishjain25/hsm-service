package com.tmobile.hsmservice.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.tmobile.hsmservice.dto.AesKeyDTO;
import com.tmobile.hsmservice.dto.HsmDTOUtil;
import com.tmobile.hsmservice.dto.RSAKeyPairDTO;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import jakarta.annotation.PostConstruct;

@Service
public class HsmService {

	private Logger logger = LoggerFactory.getLogger(HsmService.class);

	@Value("${pkcs11.module-path}")
	private String modulePath;

	@Autowired
	private HsmServiceUtil hsmServiceUtil;

	@Autowired
	private HsmDTOUtil hsmDTOUtil;

	private Module pkcs11Module;
	
	@PostConstruct
    public void postConstructRoutine() {
        // initialize pkcs11 module
		try {
			pkcs11Module = Module.getInstance(modulePath);
			pkcs11Module.initialize(null);
		} catch (IOException e) {
			logger.error("PKCS11 Module not found at path: {}",modulePath);
			e.printStackTrace();
		} catch (TokenException e) {
			logger.error("PKCS11 Module not initialized, error: {}",e.getMessage());
			e.printStackTrace();
		}
    }
	
	
	public void getObjects() {

		// User's PIN for given slot. Can get this as an user input also.
		String userPIN = "1234";
		try {
			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

			logger.info("Total slots: {}", slotsWithTokens.length);
			// Assume that you've configured slot 0000, get the token of slotsWithTokens[0]
			Token token = slotsWithTokens[0].getToken();
			logger.info("Token ID: {}", token.getTokenID());
			Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RW_SESSION, null, null);
			// Login to the session.
			session.login(Session.UserType.USER, userPIN.toCharArray());

			// Perform the required cryptographic operation here.
			// find private RSA keys that the application can use for signing - START HERE
			RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
			privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

			session.findObjectsInit(privateSignatureKeyTemplate);
			Object[] privateSignatureKeys;

			List signatureKeyList = new Vector(4);
			while ((privateSignatureKeys = session.findObjects(1)).length > 0) {
				logger.info("private key: {}", privateSignatureKeys[0]);
				signatureKeyList.add(privateSignatureKeys[0]);
			}
			session.findObjectsFinal();

			// Close the session.
			session.closeSession();
		} catch (TokenException exception) {
			exception.printStackTrace();
			logger.error("Error observed: {}", exception.getCause());
			logger.error("Error observed: {}", exception.getLocalizedMessage());
		}
	}

	public RSAKeyPairDTO saveKeyPair(long slotId, String userpin, String imei) {
		try {

			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

			Optional<Slot> matchedSlot = Arrays.asList(slotsWithTokens).stream()
					.filter(slot -> slot.getSlotID() == slotId).findFirst();

			if (matchedSlot.get() == null)
				return null;

			logger.info("Slot ID:{}", matchedSlot.get().getSlotID());

			Session session = matchedSlot.get().getToken().openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RW_SESSION, null, null);
			// Login to the session.
			session.login(Session.UserType.USER, userpin.toCharArray());

			RSAPublicKey publicKeyTemplate = new RSAPublicKey();
			RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
			/*
			 * publicKeyTemplate.removeAttribute(0); privateKeyTemplate.removeAttribute(0);
			 * publicKeyTemplate.removeAttribute(256);
			 * privateKeyTemplate.removeAttribute(256);
			 */	
			//logger.info("******************* Private attributes: {}",privateKeyTemplate.getSetAttributes());
			
			byte[] publicExponentBytes = { 0x01, 0x00, 0x001 };
			publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
			publicKeyTemplate.getModulusBits().setLongValue(2048l);
		
			
			KeyPair generatedKeyPair = hsmServiceUtil.generateRSAKeyPair(session, privateKeyTemplate,
					publicKeyTemplate,imei);

			// Close the session.
			session.closeSession();

			if (generatedKeyPair != null) {
				logger.info("RSA key pair successfully generated!");
				return hsmDTOUtil.createRsaKeyPairDTO(generatedKeyPair);
			}

		} catch (TokenException exception) {
			exception.printStackTrace();
			logger.error("Error observed: {}", exception.getLocalizedMessage());
		}

		return null;
	}

	public AesKeyDTO saveAESKey(long slotId, String userPin, String label) {
		try {

			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

			Optional<Slot> matchedSlot = Arrays.asList(slotsWithTokens).stream()
					.filter(slot -> slot.getSlotID() == slotId).findFirst();
			if (matchedSlot.get() == null)
				return null;

			logger.info("Slot ID:{}, Token ID: {}", matchedSlot.get().getSlotID(),
					matchedSlot.get().getToken().getTokenID());
			Session session = matchedSlot.get().getToken().openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RW_SESSION, null, null);
			// Login to the session.
			session.login(Session.UserType.USER, userPin.toCharArray());

			AESSecretKey generatedSecretKey = hsmServiceUtil.createAESKey(session, label.toCharArray());

			// Close the session.
			session.closeSession();

			if (generatedSecretKey != null) {
				logger.info("AES key successfully generated!");
				return hsmDTOUtil.createAesKeyDTO(generatedSecretKey);
			}

		} catch (TokenException exception) {
			exception.printStackTrace();
			logger.error("Error observed, cause: {}", exception.getCause());
			logger.error("Error observed, message: {}", exception.getLocalizedMessage());
		}
		return null;
	}

}
