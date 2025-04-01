package com.tmobile.hsmservice.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.CreateKeyRingRequest;
import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.CryptoKey.CryptoKeyPurpose;
import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.CryptoKeyVersionTemplate;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceClient.ListCryptoKeysPagedResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient.ListKeyRingsPagedResponse;
import com.google.cloud.kms.v1.KeyRing;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.kms.v1.LocationName;
import com.google.cloud.kms.v1.ProtectionLevel;
import com.google.cloud.kms.v1.PublicKey;
import com.google.protobuf.ByteString;
import com.tmobile.hsmservice.controller.HsmGoogleController;
import com.tmobile.hsmservice.dto.CryptoKeyDTO;

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

		logger.info("Key ring to be created with id: {}", keyringId);

		// Initialize client that will be used to send requests. This client only
		// needs to be created once, and can be reused for multiple requests. After
		// completing all of your requests, call the "close" method on the client to
		// safely clean up any remaining background resources.
		try (KeyManagementServiceClient keyManagementServiceClient = KeyManagementServiceClient.create()) {
			CreateKeyRingRequest request = CreateKeyRingRequest.newBuilder()
					.setParent(LocationName.of(projectId, location).toString()).setKeyRingId(keyringId)
					.setKeyRing(KeyRing.newBuilder().build()).build();

			return keyManagementServiceClient.createKeyRing(request);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

	}

	public CryptoKey createCryptoKey(String keyringId, CryptoKeyDTO cryptoKeyDTO) {

		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {

			KeyRingName keyRingName = KeyRingName.of(projectId, location, keyringId);

			CryptoKey key = CryptoKey.newBuilder().setPurpose(CryptoKeyPurpose.valueOf(cryptoKeyDTO.purpose()))
					.setVersionTemplate(CryptoKeyVersionTemplate.newBuilder()
							.setAlgorithm(CryptoKeyVersionAlgorithm.valueOf(cryptoKeyDTO.alogirthm()))
							.setProtectionLevel(ProtectionLevel.valueOf(cryptoKeyDTO.protectionlevel())))
					.putAllLabels(cryptoKeyDTO.labels()).build();

			return client.createCryptoKey(keyRingName, cryptoKeyDTO.name(), key);
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

	public boolean encryptData(String keyringId, String keyId, String data) {

		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {

			// Build the key version name from the project, location, key ring, key,
			// and key version.
			CryptoKeyName keyVersionName = CryptoKeyName.of(projectId, location, keyringId, keyId);

			// Encrypt the plaintext.
			EncryptResponse encryptResponse = client.encrypt(keyVersionName, ByteString.copyFromUtf8(data));
			logger.info("Encrypted Text (Base64 encoded): {}", Base64.getEncoder().encodeToString(encryptResponse.getCiphertext().toByteArray()));

			DecryptResponse decryptResponse = client.decrypt(keyVersionName, encryptResponse.getCiphertext());
			logger.info("Decrypted Text: {}", decryptResponse.getPlaintext().toStringUtf8());
			return true;

		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}

	}

	public boolean encryptDataAsymmetric(String keyringId, String keyId, String data) {

		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {

			// Build the key version name from the project, location, key ring, key,
			// and key version.

			CryptoKeyVersionName keyVersionName = CryptoKeyVersionName.of(projectId, location, keyringId, keyId, "1");

			// Get the public key.
			PublicKey publicKey = client.getPublicKey(keyVersionName);

			// Convert the public PEM key to a DER key
			byte[] derKey = convertPemToDer(publicKey.getPem());
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
			java.security.PublicKey rsaKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

			// Encrypt data using 'RSA_DECRYPT_OAEP_2048_SHA256' key.
			// Refer https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
					PSource.PSpecified.DEFAULT);
			cipher.init(Cipher.ENCRYPT_MODE, rsaKey, oaepParams);
			byte[] ciphertext = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
			logger.info("Encrypted text (Base64 encoded): {}", Base64.getEncoder().encodeToString(ciphertext));
			decryptDataAsymmetric(keyringId, keyId, ciphertext);
			return true;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		}

	}

	public boolean decryptDataAsymmetric(String keyringId, String keyId, byte[] ciphertext) {

		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
			CryptoKeyVersionName keyVersionName = CryptoKeyVersionName.of(projectId, location, keyringId, keyId, "1");

			// Decrypt the ciphertext.
			AsymmetricDecryptResponse response = client.asymmetricDecrypt(keyVersionName,
					ByteString.copyFrom(ciphertext));
			logger.info("Decrypted Text: {}", response.getPlaintext().toStringUtf8());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	// Converts a base64-encoded PEM certificate like the one returned from Cloud
	// KMS into a DER formatted certificate for use with the Java APIs.
	private byte[] convertPemToDer(String pem) {
		BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
		String encoded = bufferedReader.lines()
				.filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
				.collect(Collectors.joining());
		return Base64.getDecoder().decode(encoded);
	}

	public boolean signDataAndVerifySignature(String keyringId, String keyId, String data) {

		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
			// Build the key version name from the project, location, key ring, key,
			// and key version.
			CryptoKeyVersionName keyVersionName = CryptoKeyVersionName.of(projectId, location, keyringId, keyId, "1");

			// Convert the message into bytes. Cryptographic plaintexts and
			// ciphertexts are always byte arrays.
			byte[] plaintext = data.getBytes(StandardCharsets.UTF_8);

			byte[] signature = signData(client, keyVersionName, plaintext);
			verifySignature(client, keyVersionName, plaintext, signature);
			return true;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		} catch (IOException e1) {
			e1.printStackTrace();
			return false;
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		}

	}

	private byte[] signData(KeyManagementServiceClient client, CryptoKeyVersionName keyVersionName,
			byte[] plaintext) throws NoSuchAlgorithmException {
		// Calculate the digest.
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] hash = sha256.digest(plaintext);

		// Build the digest object.
		Digest digest = Digest.newBuilder().setSha256(ByteString.copyFrom(hash)).build();

		// Sign the digest.
		AsymmetricSignResponse result = client.asymmetricSign(keyVersionName, digest);

		// Get the signature.
		byte[] signature = result.getSignature().toByteArray();

		logger.info("Signature (Base64 encoded): {}", Base64.getEncoder().encodeToString(signature));
		return signature;
	}

	private void verifySignature(KeyManagementServiceClient client, CryptoKeyVersionName keyVersionName,
			byte[] plaintext, byte[] signature) throws NoSuchAlgorithmException, GeneralSecurityException {
		// Get the public key.
		PublicKey publicKey = client.getPublicKey(keyVersionName);

		// Convert the public PEM key to a DER key (see helper below).
		byte[] derKey = convertPemToDer(publicKey.getPem());
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
		java.security.PublicKey rsaKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

		// Verify the 'RSA_SIGN_PKCS1_2048_SHA256' signature.
		// For other key algorithms:
		// http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature
		Signature rsaVerify = Signature.getInstance("SHA256withRSA");
		rsaVerify.initVerify(rsaKey);
		rsaVerify.update(plaintext);

		// Verify the signature.
		boolean verified = rsaVerify.verify(signature);
		logger.info("Signature verified: {}", verified);

	}
}
