package com.tmobile.hsmservice.service;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.google.cloud.kms.v1.CreateKeyRingRequest;
import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.CryptoKey.CryptoKeyPurpose;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionTemplate;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceClient.ListCryptoKeysPagedResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient.ListKeyRingsPagedResponse;
import com.google.cloud.kms.v1.KeyRing;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.kms.v1.LocationName;
import com.tmobile.hsmservice.controller.HsmGoogleController;

@Service
public class HsmGoogleService {

	private Logger logger = LoggerFactory.getLogger(HsmGoogleController.class);
	
	@Value("${hsm.google-cloud.project-id}")
	private String projectId;
	
	@Value("${hsm.google-cloud.location}")
	private String location;
	
	public ListKeyRingsPagedResponse getKeyRings() {
		// Initialize client that will be used to send requests. This client only
		// needs to be created once, and can be reused for multiple requests. After
		// completing all of your requests, call the "close" method on the client to
		// safely clean up any remaining background resources.
		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
			// Build the parent from the project and location.
			LocationName parent = LocationName.of(projectId, location);

			// Call the API to get key rings.
			ListKeyRingsPagedResponse response = client.listKeyRings(parent);
		
			return response;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public KeyRing createKeyRing(String keyringId) {
		
		logger.info("Key ring to be created with id: {}",keyringId);
		
		// Initialize client that will be used to send requests. This client only
		// needs to be created once, and can be reused for multiple requests. After
		// completing all of your requests, call the "close" method on the client to
		// safely clean up any remaining background resources.
		try (KeyManagementServiceClient keyManagementServiceClient =
			     KeyManagementServiceClient.create()) {
			   CreateKeyRingRequest request =
			       CreateKeyRingRequest.newBuilder()
			           .setParent(LocationName.of(projectId, location).toString())
			           .setKeyRingId(keyringId)
			           .setKeyRing(KeyRing.newBuilder().build())
			           .build();
			   
			  return keyManagementServiceClient.createKeyRing(request);
			 } catch (IOException e) {
				e.printStackTrace();
				return null;
			}

	}
	
	public CryptoKey createCryptoKey(String keyringId, String keyId) {
	  
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            // Build the parent name from the project, location, and key ring.
            KeyRingName keyRingName = KeyRingName.of(projectId, location, keyringId);

            // Build the key to create with labels.
            CryptoKey key =
                CryptoKey.newBuilder()
                    .setPurpose(CryptoKeyPurpose.ENCRYPT_DECRYPT)
                    .setVersionTemplate(
                        CryptoKeyVersionTemplate.newBuilder()
                            .setAlgorithm(CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION))
                    .putLabels("team", "alpha")
                    .putLabels("cost_center", "cc1234")
                    .build();

            // Create the key.
            CryptoKey createdKey = client.createCryptoKey(keyRingName, keyId, key);
            System.out.printf("Created key with labels %s%n", createdKey.getName());
            return createdKey;
          } catch (IOException e) {
			e.printStackTrace();
			return null;
		}
        
	}
	
	public ListCryptoKeysPagedResponse getCryptoKeys(String keyRingId) {
		// Initialize client that will be used to send requests. This client only
		// needs to be created once, and can be reused for multiple requests. After
		// completing all of your requests, call the "close" method on the client to
		// safely clean up any remaining background resources.
		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
			// Build the parent from the project and location.
			
			KeyRingName keyRingName = KeyRingName.of(projectId, location, keyRingId);
			// Call the API to get key rings.
			return client.listCryptoKeys(keyRingName);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
}
