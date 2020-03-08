package com.redteamobile.employee;

import com.redteamobile.credential.CredentialUtils;
import com.redteamobile.credential.Crypto;
import com.redteamobile.employee.utils.CertificateUtils;
import com.redteamobile.employee.utils.CompressUtils;
import org.apache.tomcat.util.buf.HexUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.List;

//@RunWith(SpringRunner.class)
@SpringBootTest
public class EmployeeApplicationTests {

	private static final String CMCertPath = "src/main/resources/cert/CM.pem";

	@Autowired
	private RedisTemplate<String, List<String>> certRelationship;

	@Test
	public void contextLoads() {
	}

	@Test
	public void testKeyPair() throws Exception{

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

	@Test
	public void testFile() throws Exception{
		String filePath = "/Users/redtea/Desktop/2020";
		File file = new File(filePath);
		file.mkdir();
		File fileA = new File(file.getPath() + "/aaa");
		fileA.mkdir();
		File fileB = new File(file.getPath() + "/bbb");
		fileB.mkdir();
		File file1 = new File(fileA.getPath()  + "/111.txt");
		file1.createNewFile();
		File file2 = new File(fileA.getPath() + "/222.txt");
		file2.createNewFile();
		File file3 = new File(fileB.getPath() + "/111.txt");
		file3.createNewFile();
		File file4 = new File(fileB.getPath() + "/222.txt");
		file4.createNewFile();

		CompressUtils.CompressWithoutFolder(filePath , filePath+".zip");
	}

	@Test
	public void testKeyPairGenerator() throws Exception{
		KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
		keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("brainpoolp256r1"));
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		System.out.println(keyPair.getPublic());
	}

	@Test
	public void testAES() throws Exception{
		//System.out.println(HexUtils.toHexString(Base64Utils.decodeFromString("S7izX3H/K/XXB2E61ovzFQ==")));
		String SHARED_PROFILE_AES_KEY = "6F96CFDFE5CCC627CADF24B41725CAA4";
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
		System.out.println(HexUtils.toHexString(encryptWithAES(privateKeyBytes, HexUtils.fromHexString(SHARED_PROFILE_AES_KEY), null)));

		PublicKey publicKey = CertificateUtils.convertStringToPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXN84Q4wWe3GS6NzaQoEwcJp4yzBT4HLzTdHkCbqKezuaVTgSdOc1jrN5CtFLIJhi1cFjzTkySgG3Nt/v8yh/Lw==");

		byte[] origin = HexUtils.fromHexString("4988ce877f2c8089e4d5ddaffb7790594217c766d60020c57ff68c8c123360d4");

		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(origin);
		byte[] ooo = CredentialUtils.encodeToECDSASignature(HexUtils.fromHexString("DD094593D87325BF0B7CA01D344FB551098073A208C216AD3BB651B42779C8BCDB70EF4626602ECC59BF4359F39FBCA3176D3AC56124F7058A981D2986433BB5"));
		signature.verify(ooo);
	}

	private static byte[] encryptWithAES(byte[] data, byte[] key, byte[] initializationVector) throws Exception {
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

		Cipher cipher = null;

		if (initializationVector == null || initializationVector.length == 0) {
			cipher = Cipher.getInstance("AES/ECB/NoPadding");

			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		} else {
			IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

			cipher = Cipher.getInstance("AES/CBC/NoPadding");

			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
		}

		return cipher.doFinal(data);
	}

	@Test
	public void testFormat(){
		/*String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDLeRXBOSQRK357XJlqttpx0Sz/5y0/Q47O2ZRbkLcH7A==";
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("-----BEGIN PRIVATE KEY-----\n")
				.append(privateKey)
				.append("\n-----END PRIVATE KEY-----\n");
		System.out.println(stringBuilder.toString());*/
		String s = "-----BEGIN PRIVATE KEY-----\n" +
				"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghhV699yyrgSZVOOO\n" +
				"e2WcSX+op0lZfkGSXChVVH6p3quhRANCAATzuaDpEocQZ7lXDWxjwLmITlJt7g8K\n" +
				"Vzho4kb8akKqahS4Vj01GW0oz3V7oKScxceO2nFUBfe4aGyL1nJqf7LN\n" +
				"-----END PRIVATE KEY-----";
		String s1 = getPrivateKeyString(s);
		System.out.println(s1);

	}

	private String getPrivateKeyString(String privateKeyString){
		String result = privateKeyString.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replace("\n", "");
		return result;
	}

	@Test
	public void testRedis(){
		certRelationship.opsForValue().set("1111" , new ArrayList<>());
		List<String> list = certRelationship.opsForValue().get("1111");
		list.add("22222");
		certRelationship.opsForValue().set("1111" , list);
		System.out.println(certRelationship.opsForValue().get("1111").get(0));
	}

}
