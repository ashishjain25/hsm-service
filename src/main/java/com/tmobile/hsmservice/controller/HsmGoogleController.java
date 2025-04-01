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
import com.tmobile.hsmservice.dto.DataDTO;
import com.tmobile.hsmservice.dto.KeyRingDTO;
import com.tmobile.hsmservice.service.HsmGoogleService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
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
	
	@Operation(summary = "Get list of key rings from Google Cloud HSM.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "List of key rings from Google Cloud HSM retrieved successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed during retrieval of key rings.")})
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
	@Operation(summary = "Create a key ring in Google Cloud HSM.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Created key ring in Google Cloud HSM successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed in creation of key ring.")})
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
	
	@Operation(summary = "Create crypto key in a key ring in Google Cloud HSM.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Created crypto key in the key ring in Google Cloud HSM successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed during creation of crypto key.")})
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
				cryptoKey.getVersionTemplate().getAlgorithm().name(),
				cryptoKey.getVersionTemplate().getProtectionLevel().name(), cryptoKey.getLabelsMap());
		return new ResponseEntity<>(cryptoKeyResponse, HttpStatus.OK);
	}

	/**
	 * Get list of crypto keys
	 * 
	 * @return
	 */
	@Operation(summary = "Get list of crypto keys in a key ring from Google Cloud HSM.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "List of crypto keys from key ring in Google Cloud HSM retrieved successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed retrieval of crypto keys.")})
	@GetMapping("/cryptokey")
	public ResponseEntity<List<CryptoKeyDTO>> getCryptoKeys(
			@NotNull(message = "Please provide key ring id") @RequestParam String keyringId) {
		logger.info("Received request to get crypto keys");
		ListCryptoKeysPagedResponse pagedResponse = hsmGoogleService.getCryptoKeys(keyringId);

		List<CryptoKeyDTO> cryptoKeys = new ArrayList<>();
		for (CryptoKey cryptoKey : pagedResponse.iterateAll()) {
			logger.info("name: {}", cryptoKey.getName());
			CryptoKeyDTO cryptoKeyDTO = new CryptoKeyDTO(cryptoKey.getName(), cryptoKey.getPurpose().name(),
					cryptoKey.getVersionTemplate().getAlgorithm().name(),
					cryptoKey.getVersionTemplate().getProtectionLevel().name(), cryptoKey.getLabelsMap());
			cryptoKeys.add(cryptoKeyDTO);
		}
		if (cryptoKeys.size() == 0)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(cryptoKeys, HttpStatus.OK);
	}

	/**
	 * Encrypt data using Symmetric key in a given Project and Location.
	 * 
	 * @param keyringid
	 * @param keyid
	 * @param dataDto
	 */
	@Operation(summary = "Encrypt and decrypt data using AES key from Google Cloud HSM.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Encrypted data using AES key from Google Cloud HSM successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed encryption of data.")})
	@PostMapping("/encrypt")
	public ResponseEntity<CryptoKeyDTO> encrypt(
			@NotNull(message = "Please provide key ring id") @RequestParam String keyringid,
			@NotNull(message = "Please provide key id") @RequestParam String keyid,
			@Valid @RequestBody DataDTO dataDto) {
		logger.info("Received request to encrypt data");
		boolean retVal = hsmGoogleService.encryptData(keyringid, keyid, dataDto.data());

		if (!retVal)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		logger.info("Data encrypted/decrypted successfully");

		return new ResponseEntity<>(HttpStatus.OK);
	}

	/**
	 * Encrypt data using RSA key in a given Project and Location.
	 * 
	 * @param keyringid
	 * @param keyid
	 * @param dataDto
	 */
	@Operation(summary = "Encrypt and decrypt data using RSA key from Google Cloud HSM.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Encrypted data using RSA key from Google Cloud HSM successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed encryption of data.")})
	@PostMapping("/encryptrsa")
	public ResponseEntity<CryptoKeyDTO> encryptRsa(
			@NotNull(message = "Please provide key ring id") @RequestParam String keyringid,
			@NotNull(message = "Please provide key id") @RequestParam String keyid,
			@Valid @RequestBody DataDTO dataDto) {
		logger.info("Received request to encrypt data using rsa key");
		boolean retVal = hsmGoogleService.encryptDataAsymmetric(keyringid, keyid, dataDto.data());

		if (!retVal)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		logger.info("Data encrypted/decrypted successfully");

		return new ResponseEntity<>(HttpStatus.OK);
	}

	/**
	 * Digitally sign and verify data using RSA key in a given Project and Location.
	 * 
	 * @param keyringid
	 * @param keyid
	 * @param dataDto
	 */
	@Operation(summary = "Digitally sign data using key from Google Cloud HSM.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Signing data using key from Google Cloud HSM is successfull."),
			@ApiResponse(responseCode = "500", description = "Some error observed data signing.")})
	@PostMapping("/sign")
	public ResponseEntity<CryptoKeyDTO> signDataAndVerifySignature(
			@NotNull(message = "Please provide key ring id") @RequestParam String keyringid,
			@NotNull(message = "Please provide key id") @RequestParam String keyid,
			@Valid @RequestBody DataDTO dataDto) {
		logger.info("Received request to digitially sign data and verify the signature");
		boolean retVal = hsmGoogleService.signDataAndVerifySignature(keyringid, keyid, dataDto.data());

		if (!retVal)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		logger.info("Data signed successfully");

		return new ResponseEntity<>(HttpStatus.OK);
	}
}
