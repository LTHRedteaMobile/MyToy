package com.redteamobile.employee;

import com.redteamobile.credential.CredentialUtils;
import com.redteamobile.credential.Crypto;
import com.redteamobile.employee.utils.CertificateUtils;
import org.apache.tomcat.util.buf.HexUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

//@RunWith(SpringRunner.class)
@SpringBootTest
public class EmployeeApplicationTests {

	@Test
	public void contextLoads() {
	}

	@Test
	public void test() throws Exception{
		byte[] origin = "2E11F8D5928F37D918797ECC46C9B763".getBytes();
        PrivateKey privateKey = CertificateUtils.convertStringToPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjXvaXLFq5Xwdt+iEFSmNfjn0Z48SaB9oxo6HxAVv2f2hRANCAAS6Ih1FmAk7c1RkxZQljBM8L7eXXC3Xmp0WDGFtRD6/sF7ZVBcRF1wnPh+5sBwXYYcaTR49IVKyoAboJTmrvrJd");

        byte[] output = CredentialUtils.sign(origin, privateKey, Crypto.ECDSA);
        System.out.println(Base64Utils.encodeToString(output));
	}

	@Test
	public void testVerifySKBSignature() throws Exception{
		//byte[] origin = {0x72, 0x65, 0x64, 0x74, 0x65, 0x61, 0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65};
		byte[] origin = "redteamobile".getBytes();
		System.out.println(HexUtils.toHexString(origin));
		PublicKey publicKey = CertificateUtils.convertStringToPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXN84Q4wWe3GS6NzaQoEwcJp4yzBT4HLzTdHkCbqKezuaVTgSdOc1jrN5CtFLIJhi1cFjzTkySgG3Nt/v8yh/Lw==");

		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(origin);
		byte[] ooo = CredentialUtils.encodeToECDSASignature(HexUtils.fromHexString("2E7C7F6FAFBAA392803A2B569E8020147CB9FBCB8A1A55F4B9C36AE76F0ABA036B0CDFE4E82CCF5A620AEBD6754EC92AD2A4DDAFBE7805C932380E2E56D57A3A"));
		signature.verify(ooo);
		//System.out.println(Base64Utils.encodeToString(HexUtils.fromHexString("85DDE5ED25512CC6D64695FFE67049C2366EBE57A9BA6390C776C46AF7703AB91E3FE48571CA630A0EE4C7FDFC8BE9367F61D0D1B037A4AF497036C22CD0C568")));
	}

	@Test
	public void testEncrypt() throws Exception{
		byte[] origin = "redteamobile".getBytes();
		System.out.println(HexUtils.toHexString(origin));
		PublicKey publicKey = CertificateUtils.convertStringToPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXN84Q4wWe3GS6NzaQoEwcJp4yzBT4HLzTdHkCbqKezuaVTgSdOc1jrN5CtFLIJhi1cFjzTkySgG3Nt/v8yh/Lw==");
		PrivateKey privateKey = CertificateUtils.convertStringToPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7qY/cOTpOm/rfqex" +
				"60hGyGPKyYqG+BvaHrRlLZx4pY+hRANCAARc3zhDjBZ7cZLo3NpCgTBwmnjLMFPg" +
				"cvNN0eQJuop7O5pVOBJ05zWOs3kK0UsgmGLVwWPNOTJKAbc23+/zKH8v");
		byte[] result = encryptWithECC(origin, publicKey);
		System.out.println(HexUtils.toHexString(result));
		System.out.println(new String(decryptWithEcc(result, privateKey)));
	}

	@Test
	public void testPrivateKey() throws Exception{
		ECPrivateKey privateKey = (ECPrivateKey) CertificateUtils.convertStringToPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7qY/cOTpOm/rfqex" +
				"60hGyGPKyYqG+BvaHrRlLZx4pY+hRANCAARc3zhDjBZ7cZLo3NpCgTBwmnjLMFPg" +
				"cvNN0eQJuop7O5pVOBJ05zWOs3kK0UsgmGLVwWPNOTJKAbc23+/zKH8v");

		System.out.println(HexUtils.toHexString(privateKey.getS().toByteArray()));

		//ECPrivateKey privateKey2 = (ECPrivateKey) CertificateUtils.convertStringToPrivateKey("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4ZXCdCWeNSPTpvUK" +
				//"KRsZKHURnxKbniE2sq7a8qo67lOhRANCAAR7ryt+AvDu5vZSSiWk8EnJUM3Vz8hj" +
				//"1Q53In4RepbmhCW8foa2eSLECGZ6jbekdEv7PT744KupXXzf6qJTJmS7");
		//System.out.println(privateKey2.getS().toByteArray().length);

		//System.out.println(HexUtils.toHexString(privateKey2.getS().toByteArray()));

		byte[] privateKeyBytes = new byte[32];
		System.arraycopy(privateKey.getS().toByteArray(), 1, privateKeyBytes, 0, 32);
		System.out.println(HexUtils.toHexString(privateKeyBytes));

		PublicKey publicKeyForEncrypt = CertificateUtils.convertStringToPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7D9p0A1mgls2ZN9fHsDkRQUKEe3+" +
				"0F3sTFBa/AO2lcR+y6h9xF0SM4ADT04ZvRILwSioQoZ6jdtMuHRU/WK65w==");


		System.out.println(HexUtils.toHexString(encryptWithECC(privateKeyBytes, publicKeyForEncrypt)));


	}

	private static byte[] encryptWithECC(byte[] date, PublicKey publicKey) throws Exception{
		//Cipher cipher = new NullCipher();
		Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(date);
	}

	private static byte[] decryptWithEcc(byte[] date, PrivateKey privateKey) throws Exception{
		//Cipher cipher = new NullCipher();
		Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(date);
	}


}
