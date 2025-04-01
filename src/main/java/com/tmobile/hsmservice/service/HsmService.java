package com.tmobile.hsmservice.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.tmobile.hsmservice.dto.AesKeyDTO;
import com.tmobile.hsmservice.dto.KeyDTO;
import com.tmobile.hsmservice.dto.PrivateKeyDTO;
import com.tmobile.hsmservice.dto.PublicKeyDTO;
import com.tmobile.hsmservice.dto.RSAKeyPairDTO;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

@Service
public class HsmService {

	private Logger logger = LoggerFactory.getLogger(HsmService.class);

	@Value("${pkcs11.module-path}")
	private String modulePath;

	@Autowired
	private HsmServiceUtil hsmServiceUtil;

	@Autowired
	private HsmResponseUtil hsmDTOUtil;

	private Module pkcs11Module;

	@PostConstruct
	public void postConstructRoutine() {
		// initialize pkcs11 module
		try {
			pkcs11Module = Module.getInstance(modulePath);
			pkcs11Module.initialize(null);
			logger.info("PKCS11 module initialized successfully");
		} catch (IOException e) {
			logger.error("PKCS11 Module not found at path: {}", modulePath);
			e.printStackTrace();
		} catch (TokenException e) {
			logger.error("PKCS11 Module not initialized, error: {}", e.getMessage());
			e.printStackTrace();
		}
	}

	@PreDestroy
	public void preDestroyRoutine() {
		// destroy pkcs11 module
		try {
			pkcs11Module.finalize(null);
		} catch (TokenException e) {
			logger.error("PKCS11 Module not destroyed, error: {}", e.getMessage());
			e.printStackTrace();
		}
	}

	public KeyDTO getObjects(String userPin, long slotId) {
		Session session = null;
		try {
			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
			Optional<Slot> matchedSlot = Arrays.asList(slotsWithTokens).stream()
					.filter(slot -> slot.getSlotID() == slotId).findFirst();

			if (matchedSlot.isEmpty())
				throw new IllegalArgumentException("Invalid slotId :0x" + Long.toHexString(slotId));

			logger.info("Slot ID:0x{}", Long.toHexString(matchedSlot.get().getSlotID()));

			session = matchedSlot.get().getToken().openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RO_SESSION, null, null);

			// Login to the session.
			session.login(Session.UserType.USER, userPin.toCharArray());

			List<PrivateKey> privateKeys = hsmServiceUtil.getPrivateKeys(session);

			List<PrivateKeyDTO> privateKeyDTOs = privateKeys.stream()
					.filter(privateKey -> Objects.nonNull(privateKey.getLabel().getCharArrayValue()))
					.map(privateKey -> new PrivateKeyDTO(privateKey.getLabel().getCharArrayValue()))
					.collect(Collectors.toList());

			List<PublicKey> publicKeys = hsmServiceUtil.getPublicKeys(session);

			List<PublicKeyDTO> publicKeyDTOs = publicKeys.stream()
					.filter(publicKey -> Objects.nonNull(publicKey.getLabel().getCharArrayValue()))
					.map(publicKey -> new PublicKeyDTO(publicKey.getLabel().getCharArrayValue()))
					.collect(Collectors.toList());

			List<AESSecretKey> aesKeys = hsmServiceUtil.getAESKeys(session);

			List<AesKeyDTO> aesKeyDTOs = aesKeys.stream()
					.filter(aesKey -> Objects.nonNull(aesKey.getLabel().getCharArrayValue()))
					.map(aesKey -> new AesKeyDTO(aesKey.getLabel().getCharArrayValue())).collect(Collectors.toList());

			KeyDTO keyDTO = new KeyDTO(privateKeyDTOs, publicKeyDTOs, aesKeyDTOs);
			logger.info("Objects stored on token '{}' successfully retrieved!",
					matchedSlot.get().getToken().getTokenInfo().getLabel().trim());
			return keyDTO;
		} catch (TokenException exception) {
			exception.printStackTrace();
			logger.error("Error observed: {}", exception.getCause());
			logger.error("Error observed: {}", exception.getLocalizedMessage());
		} finally {
			try {
				if (Objects.nonNull(session))
					session.closeSession();
			} catch (TokenException e) {
				logger.error("Error observed in closing the session: {}", e.getLocalizedMessage());
				e.printStackTrace();
			}
		}
		return null;
	}

	public RSAKeyPairDTO saveKeyPair(long slotId, String userpin, String label) {
		Session session = null;
		try {

			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

			Optional<Slot> matchedSlot = Arrays.asList(slotsWithTokens).stream()
					.filter(slot -> slot.getSlotID() == slotId).findFirst();

			if (matchedSlot.isEmpty())
				throw new IllegalArgumentException("Invalid slotId :0x" + Long.toHexString(slotId));

			logger.info("Slot ID:0x{}", Long.toHexString(matchedSlot.get().getSlotID()));

			session = matchedSlot.get().getToken().openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RW_SESSION, null, null);
			// Login to the session.
			session.login(Session.UserType.USER, userpin.toCharArray());

			KeyPair generatedKeyPair = hsmServiceUtil.generateRSAKeyPair(session, label);

			if (generatedKeyPair != null) {
				logger.info("RSA key pair successfully generated!");
				return hsmDTOUtil.createRsaKeyPairDTO(generatedKeyPair);
			}

		} catch (TokenException exception) {
			exception.printStackTrace();
			logger.error("Error observed: {}", exception.getLocalizedMessage());
			return hsmDTOUtil.createRsaKeyPairDTO(hsmServiceUtil.getPrivateKey(), hsmServiceUtil.getPublicKey());
		} finally {
			try {
				session.logout();
				session.closeSession();
			} catch (TokenException e) {
				logger.error("Error observed in closing the session: {}", e.getLocalizedMessage());
				e.printStackTrace();
			}
		}

		return null;
	}

	public AesKeyDTO saveAESKey(long slotId, String userPin, String label) {
		Session session = null;
		try {

			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

			Optional<Slot> matchedSlot = Arrays.asList(slotsWithTokens).stream()
					.filter(slot -> slot.getSlotID() == slotId).findFirst();

			if (matchedSlot.isEmpty())
				throw new IllegalArgumentException("Invalid slotId :0x" + Long.toHexString(slotId));

			logger.info("Slot ID:0x{}", Long.toHexString(matchedSlot.get().getSlotID()));
			session = matchedSlot.get().getToken().openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RW_SESSION, null, null);
			// Login to the session.
			session.login(Session.UserType.USER, userPin.toCharArray());

			AESSecretKey generatedSecretKey = hsmServiceUtil.createAESKey(session, label.toCharArray());

			if (generatedSecretKey != null) {
				logger.info("AES key successfully generated!");
				return hsmDTOUtil.createAesKeyDTO(generatedSecretKey);
			}

		} catch (TokenException exception) {
			logger.error("Error observed, message: {}", exception.getLocalizedMessage());
			return hsmDTOUtil.createAesKeyDTO(hsmServiceUtil.getAesSecretKey());
		} finally {
			try {
				session.logout();
				session.closeSession();
			} catch (TokenException e) {
				logger.error("Error observed in closing the session: {}", e.getLocalizedMessage());
				e.printStackTrace();
			}
		}
		return null;
	}

	public boolean encryptData(long slotId, String userPin, String keyLabel, String data) {
		Session session = null;
		try {

			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

			Optional<Slot> matchedSlot = Arrays.asList(slotsWithTokens).stream()
					.filter(slot -> slot.getSlotID() == slotId).findFirst();

			if (matchedSlot.isEmpty())
				throw new IllegalArgumentException("Invalid slotId :0x" + Long.toHexString(slotId));

			logger.info("Slot ID:0x{}", Long.toHexString(matchedSlot.get().getSlotID()));
			session = matchedSlot.get().getToken().openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RO_SESSION, null, null);
			// Login to the session.

			session.login(Session.UserType.USER, userPin.toCharArray());

			// Encrypt data using Public Key.
			logger.info("Data '{}' to be encrypted using public key labelled {}", data, keyLabel);
			session.encryptInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS),
					hsmServiceUtil.getPublicKey(session, keyLabel));
			byte[] encryptedData = session.encrypt(data.getBytes());
			logger.info("Encrypted text (Base64 encoded): {}", Base64.getEncoder().encodeToString(encryptedData));

			// Decrypt data using Private Key.
			session.decryptInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS),
					hsmServiceUtil.getPrivateKey(session, keyLabel));
			logger.info("Data to be decrypted using private key");
			byte[] decryptedDataBytes = session.decrypt(encryptedData);
			String decryptdata = new String(decryptedDataBytes, StandardCharsets.UTF_8);
			logger.info("Data decrypted successfully: {}", decryptdata);

		} catch (TokenException exception) {
			exception.printStackTrace();
			logger.error("Error observed, message: {}", exception.getLocalizedMessage());

		} finally {
			try {
				session.logout();
				session.closeSession();
			} catch (TokenException e) {
				logger.error("Error observed in closing the session: {}", e.getLocalizedMessage());
				e.printStackTrace();
			}
		}
		return true;

	}

	public boolean signData(long slotId, String userPin, String keyLabel, String data) {
		Session session = null;
		try {

			// Get list of slots with tokens.
			Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

			Optional<Slot> matchedSlot = Arrays.asList(slotsWithTokens).stream()
					.filter(slot -> slot.getSlotID() == slotId).findFirst();

			if (matchedSlot.isEmpty())
				throw new IllegalArgumentException("Invalid slotId :0x" + Long.toHexString(slotId));

			logger.info("Slot ID:0x{}", Long.toHexString(matchedSlot.get().getSlotID()));
			session = matchedSlot.get().getToken().openSession(Token.SessionType.SERIAL_SESSION,
					Token.SessionReadWriteBehavior.RO_SESSION, null, null);
			// Login to the session.

			session.login(Session.UserType.USER, userPin.toCharArray());

			// Sign data to the session.
			logger.info("Data '{}' to be signed using private key", data);
			session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS),
					hsmServiceUtil.getPrivateKey(session, keyLabel));
			byte[] signedData = session.sign(data.getBytes());
			logger.info("Data signed successfully, (Base64 encoded): {}",
					Base64.getEncoder().encodeToString(signedData));

		} catch (TokenException exception) {
			exception.printStackTrace();
			logger.error("Error observed, message: {}", exception.getLocalizedMessage());

		} finally {
			try {
				session.logout();
				session.closeSession();
			} catch (TokenException e) {
				logger.error("Error observed in closing the session: {}", e.getLocalizedMessage());
				e.printStackTrace();
			}
		}
		return true;

	}
}
