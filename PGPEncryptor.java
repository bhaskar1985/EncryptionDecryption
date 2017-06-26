package com.bhaskar1985.pgp.pgpEncryptionDecryption;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * Implementation of the Bouncy Castle (BC) PGP Encryption/Decryption algorithm.
 * Used to encryptFile files
 */
public class PGPEncryptor {
	private static File publicKeyFile = new File("src/main/resources/encryption-key.txt");

	public static byte[] encrypt(byte[] data) {
		try {
			// ----- Read in the public key
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			InputStream input = classLoader.getResourceAsStream(publicKeyFile);
			PGPPublicKey key = readPublicKeyFromCol(input);
			System.out.println("Creating a temp file...");
			// create a file and write the string to it
			File tempfile = File.createTempFile("pgp", null);
			FileOutputStream fos = new FileOutputStream(tempfile);
			fos.write(data);
			fos.close();
			System.out.println("Temp file created at ");
			System.out.println(tempfile.getAbsolutePath());
			System.out
					.println("Reading the temp file to make sure that the bits were written\n--------------");
			BufferedReader isr = new BufferedReader(new FileReader(tempfile));
			String line = "";
			while ((line = isr.readLine()) != null) {
				System.out.println(line + "\n");
			}
			// find out a little about the keys in the public key ring
			System.out.println("Key Strength = " + key.getBitStrength());
			System.out.println("Algorithm = " + key.getAlgorithm());
			System.out.println("Bit strength = " + key.getBitStrength());
			System.out.println("Version = " + key.getVersion());
			System.out.println("Encryption key = " + key.isEncryptionKey()
					+ ", Master key = " + key.isMasterKey());
			int count = 0;
			for (java.util.Iterator iterator = key.getUserIDs(); iterator
					.hasNext();) {
				count++;
				System.out.println((String) iterator.next());
			}
			System.out.println("Key Count = " + count);
			// create an armored ascii file
			// FileOutputStream out = new FileOutputStream(outputfile);
			// encrypt the file
			// encryptFile(tempfile.getAbsolutePath(), out, key);
			// Encrypt the data
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			System.out.println("encrypted text length before=" + baos.size());
			_encrypt(tempfile.getAbsolutePath(), baos, key);
			System.out.println("encrypted text length=" + baos.size());
			tempfile.delete();
			return baos.toByteArray();
		} catch (PGPException e) {
			// System.out.println(e.toString());
			System.out.println(e.getUnderlyingException().toString());
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@SuppressWarnings("rawtypes")
	public static PGPPublicKey readPublicKeyFromCol(InputStream in)
			throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);
		PGPPublicKey key = null;
		Iterator rIt = pgpPub.getKeyRings();
		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator kIt = kRing.getPublicKeys();
			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}
		if (key == null) {
			throw new IllegalArgumentException(
					"Can't find encryption key in key ring.");
		}
		return key;
	}

	//
	// Private class method _encrypt
	//
	private static void _encrypt(String fileName, OutputStream out,
			PGPPublicKey encKey) throws IOException, NoSuchProviderException,
			PGPException {
		out = new DataOutputStream(out);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		System.out.println("creating comData...");
		// get the data from the original file
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
				PGPCompressedDataGenerator.ZIP);
		PGPUtil.writeFileToLiteralData(comData.open(bOut),
				PGPLiteralData.BINARY, new File(fileName));
		comData.close();
		System.out.println("comData created...");
		System.out.println("using PGPEncryptedDataGenerator...");
		// object that encrypts the data
		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
				PGPEncryptedDataGenerator.CAST5, new SecureRandom(), "BC");
		cPk.addMethod(encKey);
		System.out.println("used PGPEncryptedDataGenerator...");
		// take the outputstream of the original file and turn it into a byte
		// array
		byte[] bytes = bOut.toByteArray();
		System.out.println("wrote bOut to byte array...");
		// write the plain text bytes to the armored outputstream
		OutputStream cOut = cPk.open(out, bytes.length);
		cOut.write(bytes);
		cPk.close();
		out.close();
	}
}
