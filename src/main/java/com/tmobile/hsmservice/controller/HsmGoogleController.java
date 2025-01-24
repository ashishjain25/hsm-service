package com.tmobile.hsmservice.controller;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.KeyManagementServiceClient.ListCryptoKeysPagedResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient.ListKeyRingsPagedResponse;
import com.google.cloud.kms.v1.KeyRing;
import com.tmobile.hsmservice.dto.CryptoKeyDTO;
import com.tmobile.hsmservice.dto.KeyRingDTO;
import com.tmobile.hsmservice.service.HsmGoogleService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@RestController
@RequestMapping("/hsm/google")
public class HsmGoogleController {

	private Logger logger = LoggerFactory.getLogger(HsmGoogleController.class);

	@Autowired
	private HsmGoogleService hsmGoogleService;

	/**
	 * Get list of key rings
	 * 
	 * @return
	 */
	@GetMapping("/keyring")
	public ResponseEntity<List<KeyRingDTO>> getKeyRing() {
		logger.info("Received request to get key rings");
		ListKeyRingsPagedResponse pagedResponse = hsmGoogleService.getKeyRings();

		List<KeyRingDTO> keyrings = new ArrayList<>();
		for (KeyRing keyRing : pagedResponse.iterateAll()) {
			KeyRingDTO keyRingDTO = new KeyRingDTO(keyRing.getName());
			keyrings.add(keyRingDTO);
			logger.info("name: {}", keyRing.getName());
		}
		if (keyrings.size() == 0)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(keyrings, HttpStatus.OK);
	}

	/**
	 * Create a new key ring
	 * 
	 * @param id
	 * @return the newly created key ring
	 */
	@PostMapping("/keyring")
	public ResponseEntity<KeyRingDTO> createKeyRing(
			@Valid @NotNull(message = "Please provide key ring id") @RequestParam String keyringid) {
		logger.info("Received request to create key ring");
		KeyRing keyring = hsmGoogleService.createKeyRing(keyringid);

		if (keyring == null)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		logger.info("Key ring {} created successfully", keyring.getName());

		KeyRingDTO keyRingResponse = new KeyRingDTO(keyring.getName());
		return new ResponseEntity<>(keyRingResponse, HttpStatus.OK);
	}

	/**
	 * Create a new key ring in a given Project and Location.
	 * 
	 * @param id
	 * @param cryptoDTO
	 * @return the newly created key ring
	 */
	@PostMapping("/cryptokey")
	public ResponseEntity<CryptoKeyDTO> createCryptoKey(
			@NotNull(message = "Please provide key ring id") @RequestParam String keyringid,
			@Valid @RequestBody CryptoKeyDTO cryptoDto) {
		logger.info("Received request to create crypto key");
		CryptoKey cryptoKey = hsmGoogleService.createCryptoKey(keyringid, cryptoDto);

		if (cryptoKey == null)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		logger.info("Crypto key {} created successfully", cryptoKey.getName());

		CryptoKeyDTO cryptoKeyResponse = new CryptoKeyDTO(cryptoKey.getName(), cryptoKey.getPurpose().name(),
				cryptoKey.getVersionTemplate().getAlgorithm().name(),cryptoKey.getLabelsMap());
		return new ResponseEntity<>(cryptoKeyResponse, HttpStatus.OK);
	}
	/**
	 * Get list of crypto keys
	 * 
	 * @return
	 */
	@GetMapping("/cryptokey")
	public ResponseEntity<List<CryptoKeyDTO>> getCryptoKeys(
			@NotNull(message = "Please provide key ring id") @RequestParam String keyringId) {
		logger.info("Received request to get crypto keys");
		ListCryptoKeysPagedResponse pagedResponse = hsmGoogleService.getCryptoKeys(keyringId);

		List<CryptoKeyDTO> cryptoKeys = new ArrayList<>();
		for (CryptoKey cryptoKey : pagedResponse.iterateAll()) {
			logger.info("name: {}", cryptoKey.getName());
			CryptoKeyDTO cryptoKeyDTO = new CryptoKeyDTO(cryptoKey.getName(), cryptoKey.getPurpose().name(),
					cryptoKey.getVersionTemplate().getAlgorithm().name(),cryptoKey.getLabelsMap());
			cryptoKeys.add(cryptoKeyDTO);
		}
		if (cryptoKeys.size() == 0)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(cryptoKeys, HttpStatus.OK);
	}
}
