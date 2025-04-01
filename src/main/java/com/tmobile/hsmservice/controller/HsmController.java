package com.tmobile.hsmservice.controller;

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
import com.tmobile.hsmservice.dto.AesKeyDTO;
import com.tmobile.hsmservice.dto.DataDTO;
import com.tmobile.hsmservice.dto.KeyDTO;
import com.tmobile.hsmservice.dto.RSAKeyPairDTO;
import com.tmobile.hsmservice.service.HsmService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.constraints.NotNull;

@RestController
@RequestMapping("/hsm")
public class HsmController {

	private Logger logger = LoggerFactory.getLogger(HsmController.class);

	@Autowired
	private HsmService hsmService;

	@Operation(summary = "Get list of objects i.e. keys present in a slot.")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Found the keys."),
			@ApiResponse(responseCode = "500", description = "Some error observed during retrieval of objects."),
			@ApiResponse(responseCode = "400", description = "Invalid slot id.")})
	@GetMapping("/objects")
	public ResponseEntity<KeyDTO> getStoredObjects(
			@NotNull(message = "Please provide user pin") @RequestParam String userpin,
			@NotNull(message = "Please provide slot id") @RequestParam long slotid) {
		logger.info("******************Received request to retrieve objects from HSM");
		KeyDTO keyDTO = hsmService.getObjects(userpin, slotid);
		if (keyDTO == null)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(keyDTO, HttpStatus.OK);
	}

	@Operation(summary = "Create RSA key pair in a slot")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Created RSA Key pair successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed during generation of RSA key pair."),
			@ApiResponse(responseCode = "400", description = "Invalid slot id.")})
	@PostMapping("/rsakey")
	public ResponseEntity<RSAKeyPairDTO> saveRSAKeyPair(
			@NotNull(message = "Please provide user pin") @RequestParam String userpin,
			@NotNull(message = "Please provide slot id") @RequestParam long slotid,
			@NotNull(message = "Please provide key label") @RequestParam String label) {
		logger.info("******************Received request to generate RSA key pair and store in HSM");
		RSAKeyPairDTO rsaKeyPairDTO = hsmService.saveKeyPair(slotid, userpin, label);

		if (rsaKeyPairDTO == null)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(rsaKeyPairDTO, HttpStatus.OK);
	}

	@Operation(summary = "Encrypt and decrypt data using key provided")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Data encrypted successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed during data encryption."),
			@ApiResponse(responseCode = "400", description = "Invalid slot id.")})
	@PostMapping("/encrypt")
	public ResponseEntity<RSAKeyPairDTO> encryptData(
			@NotNull(message = "Please provide user pin") @RequestParam String userpin,
			@NotNull(message = "Please provide slot id") @RequestParam long slotid,
			@NotNull(message = "Please provide key label") @RequestParam String label, @RequestBody DataDTO dataDTO) {
		logger.info("******************Received request to encrypt data");
		boolean retVal = hsmService.encryptData(slotid, userpin, label, dataDTO.data());

		if (!retVal)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(HttpStatus.OK);
	}

	@Operation(summary = "Digitally sign the data using the key")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Data signed successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed during data signing."),
			@ApiResponse(responseCode = "400", description = "Invalid slot id.")})
	@PostMapping("/sign")
	public ResponseEntity<RSAKeyPairDTO> signData(
			@NotNull(message = "Please provide user pin") @RequestParam String userpin,
			@NotNull(message = "Please provide slot id") @RequestParam long slotid,
			@NotNull(message = "Please provide key label") @RequestParam String label, @RequestBody DataDTO dataDTO) {
		logger.info("******************Received request to sign data digitally");
		boolean retVal = hsmService.signData(slotid, userpin, label, dataDTO.data());

		if (!retVal)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(HttpStatus.OK);
	}

	@Operation(summary = "Create AES key in a slot")
	@ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Created AES Key successfully."),
			@ApiResponse(responseCode = "500", description = "Some error observed during generation of AES key."),
			@ApiResponse(responseCode = "400", description = "Invalid slot id.")})
	@PostMapping("/aeskey")
	public ResponseEntity<AesKeyDTO> saveAesKey(
			@NotNull(message = "Please provide user pin") @RequestParam String userpin,
			@NotNull(message = "Please provide slot id") @RequestParam long slotid,
			@NotNull(message = "Please provide key label") @RequestParam String label) {
		logger.info("******************Received request to generate AES key and store in HSM");

		AesKeyDTO aesKeyDTO = hsmService.saveAESKey(slotid, userpin, label);

		if (aesKeyDTO == null)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(aesKeyDTO, HttpStatus.OK);

	}

}
