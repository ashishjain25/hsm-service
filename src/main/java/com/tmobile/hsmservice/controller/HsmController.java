package com.tmobile.hsmservice.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.tmobile.hsmservice.dto.AesKeyDTO;
import com.tmobile.hsmservice.dto.RSAKeyPairDTO;
import com.tmobile.hsmservice.service.HsmService;

@RestController
@RequestMapping("/hsm")
public class HsmController {

	private Logger logger = LoggerFactory.getLogger(HsmController.class);

	@Autowired
	private HsmService hsmService;
	


	@GetMapping("/objects")
	public void getStoredObjects() {
		logger.info("Received request to retrieve objects from HSM");
		hsmService.getObjects();
	}

	@PostMapping("/rsakey")
	public ResponseEntity<RSAKeyPairDTO> saveRSAKeyPair(@RequestParam String userpin, @RequestParam long slotid,
			@RequestParam String imei) {
		logger.info("Received request with userpin:{}, slot id:{} and imei:{} to generate RSA key pair and store in HSM",userpin,slotid,imei);
		RSAKeyPairDTO rsaKeyPairDTO = hsmService.saveKeyPair(slotid, userpin, imei);

		if (rsaKeyPairDTO == null)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(rsaKeyPairDTO, HttpStatus.OK);
	}
	
	@PostMapping("/aeskey")
	public ResponseEntity<AesKeyDTO> saveAesKey(@RequestParam String userpin, @RequestParam long slotid,
			@RequestParam String label) {
		logger.info("Received request with userpin:{}, slot id:{} and label:{} to generate AES key and store in HSM",userpin,slotid,label);

		AesKeyDTO aesKeyDTO = hsmService.saveAESKey(slotid, userpin, label);

		if (aesKeyDTO == null)
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

		return new ResponseEntity<>(aesKeyDTO, HttpStatus.OK);

	}

}
