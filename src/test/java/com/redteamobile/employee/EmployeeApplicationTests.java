package com.redteamobile.employee;

import com.alibaba.excel.EasyExcel;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import com.redteamobile.credential.CredentialUtils;
import com.redteamobile.credential.Crypto;
import com.redteamobile.employee.model.excel.ProfileExcel;
import com.redteamobile.employee.utils.CertificateUtils;
import com.redteamobile.employee.utils.CompressUtils;
import org.apache.tomcat.util.buf.HexUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Base64Utils;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;

//@RunWith(SpringRunner.class)
@SpringBootTest
public class EmployeeApplicationTests {

	private static final String CMCertPath = "src/main/resources/cert/CM.pem";
	private static final String CICertPath = "src/main/resources/cert/ci.pem";
	private static final String DPCertPath = "src/main/resources/cert/dp.pem";
	private static final String nuSIMCertPath = "src/main/resources/cert/nuSIM.pem";
	private static final String eumertPath = "src/main/resources/cert/eum.pem";

	private static final String euiccCertPath = "src/main/resources/cert/euicc.pem";

    private static byte[] seed =
            String.valueOf(Calendar.getInstance().getTimeInMillis() % 1000).getBytes();

    private static SecureRandom secureRandom = new SecureRandom(seed);

	private static final String KEYPAIR_GENERATE_ALGORITHM = "EC";
	private static final String EC_PARAMETER_SECP256R1 = "secp256r1";
	private static final String EC_PARAMETER_BRAINPOOLP256R1 = "brainpoolp256r1";
	private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
	private static final String BASIC_NUSIM_SUBJECT_INFO =
			"C=CN, ST=Guangdong, CN=Redtea Mobile nuSIM SIM, O=Redtea Mobile Inc., OU=Redtea Mobile nuSIM";
	private static final String SIGNATURE_ALGORITHM_NAME = "SHA-256";
	private static final String POLICY_OID = "1.3.6.1.4.1.7879.13.40.1.3";

	private static KeyPairGenerator prime256KeyPairGenerator = null;
	private static KeyPairGenerator brainpoolKeyPairGenerator = null;

	static{
		try{
			prime256KeyPairGenerator = KeyPairGenerator.getInstance(KEYPAIR_GENERATE_ALGORITHM);
			prime256KeyPairGenerator.initialize(new ECGenParameterSpec(EC_PARAMETER_SECP256R1));
			brainpoolKeyPairGenerator = KeyPairGenerator.getInstance(KEYPAIR_GENERATE_ALGORITHM, new BouncyCastleProvider());
			brainpoolKeyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec(EC_PARAMETER_BRAINPOOLP256R1));
		} catch(NoSuchAlgorithmException e){
			e.printStackTrace();
		}catch (InvalidAlgorithmParameterException e){
			e.printStackTrace();
		}
	}

	@Test
	public void contextLoads() {
	}

	private static CertificateFactory factory = null;

	@BeforeClass
	public static void setup() throws Exception{
		factory = CertificateFactory.getInstance("X.509");
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
		byte[] origin = "37219E74FC306681AE2AD75D98E1D54A".getBytes();
		System.out.println(HexUtils.toHexString(origin));
		PublicKey publicKey = CertificateUtils.convertStringToPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE15jDPW/akrKsCuZnlD68OSoIHbaqCzAbG7BbXElg+OcoyLXHxf04+CmdnT9j0Fyu+JnwezI49vi1z5aNhxIxHg==");

		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(origin);
		byte[] ooo = CredentialUtils.encodeToECDSASignature(Base64Utils.decodeFromString("iHSP5pEVLn3LEHDPV41QpRLzudnry5Rkp5U6k3Ivmtmaaw4C7KnyNEcyAXqVo772vY52rP554UsVqikUIv8L7w=="));
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
		PrivateKey privateKey = CertificateUtils.convertStringToPrivateKey("MIGVAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwR6MHgCAQEEIJO8+KFvnxltR7xUfaHKbBITI7sXbcS3vCOeaABjSW0GoAsGCSskAwMCCAEBB6FEA0IABECu38StLR0uv+VMLjm1OCkDsWTfGTi4gy9JJNDJFzRln6ddvFGdoTmCgjS1INMHsNQSpHnyy72G0UsSzM+QDQY=");

		System.out.println(privateKey);
        Security.addProvider(new BouncyCastleProvider());
        FileInputStream fileInputStream = new FileInputStream(nuSIMCertPath);
        X509Certificate nuSIMCertificate = (X509Certificate) factory.generateCertificate(fileInputStream);

        PublicKey publicKey = nuSIMCertificate.getPublicKey();

        byte[] origin = "redtea".getBytes();

        Signature signature1 = Signature.getInstance("SHA256withECDSA");
        signature1.initSign(privateKey);
        signature1.update(origin);
        byte[] result = signature1.sign();

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(origin);
        //byte[] ooo = CredentialUtils.encodeToECDSASignature(Base64Utils.decodeFromString("iHSP5pEVLn3LEHDPV41QpRLzudnry5Rkp5U6k3Ivmtmaaw4C7KnyNEcyAXqVo772vY52rP554UsVqikUIv8L7w=="));
        signature.verify(result);

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
		String s = "redtea";
		byte[] data = s.getBytes();
		byte[] key = Base64Utils.decodeFromString("37PJO2TcW7qHRUw8OwmNy20rl6X9PDpC0n/OlEQ5wxU=");

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
String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDLeRXBOSQRK357XJlqttpx0Sz/5y0/Q47O2ZRbkLcH7A==";
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("-----BEGIN PRIVATE KEY-----\n")
				.append(privateKey)
				.append("\n-----END PRIVATE KEY-----\n");
		System.out.println(stringBuilder.toString());

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
	public void testCredential() throws Exception{
		String s = "MEYCIQDr1tT34fv2ziSnzTXrrnM0FAym0d61E6Y84y6to22XcQIhAIFANsHPRGYshDw5ZX+eEqWNmeU7WQxsntVlB3zaSqaN";
		System.out.println(HexUtils.toHexString(CredentialUtils.decodeECDSASignature(Base64Utils.decodeFromString(s))));
	}

	@Test
	public void  testSign() throws Exception{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		//FileInputStream fileInputStream = new FileInputStream(CMCertPath);
		//X509Certificate cmCertificate = (X509Certificate) factory.generateCertificate(fileInputStream);

		KeyPair keyPair = getKeyPair();
		PKCS10CertificationRequest csr = generateCSRForNuSIM("890230221234567890123456", keyPair);

		//PrivateKey privateKey = CredentialUtils.decodePrivateKey(Base64Utils.decodeFromString("MHgCAQEEIAj8ZeabF9raq/iYhXsh6dU02dB/RCKs8YXg0F1EP534oAsGCSskAwMCCAEBB6FEA0IABHqc+0wGFn6l3Ycbyj8DelYdS45WVLddug0mmxkISqHNUjTwwUm0q0vbOzfyLCr3bRpSlk0S+nobzHtdKAoUx6g="));
		//PrivateKey privateKey = CertificateUtils.convertStringToPrivateKey("MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIAj8ZeabF9raq/iYhXsh6dU02dB/RCKs8YXg0F1EP534oUQDQgAEepz7TAYWfqXdhxvKPwN6Vh1LjlZUt126DSabGQhKoc1SNPDBSbSrS9s7N/IsKvdtGlKWTRL6ehvMe10oChTHqA==");

		//System.out.println(privateKey);
		String keyStoreFilePath = "src/main/resources/keystore.jks";
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(keyStoreFilePath) , "redtea".toCharArray());
		PrivateKey privateKey = (PrivateKey) keyStore.getKey("cmPrivate" , "redtea".toCharArray());
		X509Certificate cmCertificate = (X509Certificate) keyStore.getCertificate("cmPrivate");
				X509Certificate nuSIM = sign(csr , privateKey , keyPair, cmCertificate , "890230221234567890123456");
		System.out.println(Base64Utils.encodeToString(nuSIM.getEncoded()));
		System.out.println(Base64Utils.encodeToString(cmCertificate.getEncoded()));

		nuSIM.verify(cmCertificate.getPublicKey());


	}

	private KeyPair getKeyPair(){
		return brainpoolKeyPairGenerator.generateKeyPair();
	}

	private PKCS10CertificationRequest generateCSRForNuSIM(String eid , KeyPair keyPair) throws Exception{
		AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
		AlgorithmIdentifier signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_ALGORITHM);
		AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(SIGNATURE_ALGORITHM_NAME);

		ContentSigner contentSigner = new BcECContentSignerBuilder(signatureAlgorithm , digestAlgorithm).build(privateKey);

		String subjectInfo = BASIC_NUSIM_SUBJECT_INFO + ", SERIALNUMBER=" + eid;

		PKCS10CertificationRequestBuilder csrBuilder=
				new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectInfo)
						, keyPair.getPublic());
		PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);
		System.out.println("csr : " + new String(BaseEncoding.base64().encode(csr.getEncoded())));

		return csr;
	}

	private static X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, KeyPair pair, X509Certificate certificate ,String eid)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, IOException,
			OperatorCreationException, CertificateException {


		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find(SIGNATURE_ALGORITHM);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);

		AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate
				.getEncoded());
		SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair
				.getPublic().getEncoded());

		PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(inputCSR.toASN1Structure());
		//in newer version of BC such as 1.51, this is
		//PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(inputCSR);

		X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
				new X500Name("C=CN, ST=GuangDong, CN=Redtea Mobile nuSIM CM, O=Redtea Mobile Inc., OU=Redtea Mobile nuSIM"), new BigInteger(eid), new Date(
				System.currentTimeMillis()), new Date(
				System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60
						* 1000), pk10Holder.getSubject(), keyInfo);

		PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(POLICY_OID));
		myCertificateGenerator.addExtension(X509Extension.subjectKeyIdentifier ,false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(pair.getPublic()));
		myCertificateGenerator.addExtension(X509Extension.authorityKeyIdentifier , false , certificate.getExtensionValue("2.5.29.14"));
		myCertificateGenerator.addExtension(X509Extension.keyUsage , true , new KeyUsage(KeyUsage.digitalSignature));
		myCertificateGenerator.addExtension(X509Extension.certificatePolicies , true , new CertificatePolicies(policyInformation));

		ContentSigner sigGen = new BcECContentSignerBuilder(sigAlgId, digAlgId)
				.build(foo);

		X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
		Certificate eeX509CertificateStructure = holder.toASN1Structure();
		//in newer version of BC such as 1.51, this is
		//org.spongycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure();

		CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

		// Read Certificate
		InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
		X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
		is1.close();
		return theCert;
		//return null;
	}

	@Test
	public void testKeystore() throws Exception{
		//导入私钥
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream fileInputStream = new FileInputStream(CMCertPath);
		X509Certificate cmCertificate = (X509Certificate) factory.generateCertificate(fileInputStream);
		String keyStoreFilePath = "src/main/resources/nuSIMKeystore.bks";
		KeyStore keyStore = KeyStore.getInstance("BKS" , "BC");
		keyStore.load(new FileInputStream(keyStoreFilePath) , "redtea".toCharArray());
         PrivateKey privateKey = CertificateUtils.convertStringToPrivateKey("MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIAj8ZeabF9raq/iYhXsh6dU02dB/RCKs8YXg0F1EP534oUQDQgAEepz7TAYWfqXdhxvKPwN6Vh1LjlZUt126DSabGQhKoc1SNPDBSbSrS9s7N/IsKvdtGlKWTRL6ehvMe10oChTHqA==");
		keyStore.setKeyEntry("cmPrivate" , privateKey, "redtea".toCharArray(),new java.security.cert.Certificate[]{cmCertificate});
		FileOutputStream fileOutputStream = new FileOutputStream("src/main/resources/nuSIMKeystore.bks");
		keyStore.store(fileOutputStream , "redtea".toCharArray());
		fileOutputStream.close();


		//String keyStoreFilePath = "src/main/resources/keystore.jks";
		//KeyStore keyStore = KeyStore.getInstance("JKS");
		//keyStore.load(new FileInputStream(keyStoreFilePath) , "redtea".toCharArray());
		//PrivateKey privateKey = (PrivateKey) keyStore.getKey("cmPrivate" , "redtea".toCharArray());
		System.out.println(Base64Utils.encodeToString(CredentialUtils.encodePrivateKey(privateKey)));
		//FileInputStream fileInputStream = new FileInputStream(CMCertPath);
		//X509Certificate cmCertificate = (X509Certificate) factory.generateCertificate(fileInputStream);
	}

	@Test
	public void changePassword() throws Exception{
		String keyStoreFilePath = "src/main/resources/BipKeystore.jks";
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(keyStoreFilePath) , "654321".toCharArray());
		//SecretKey secretKey1 = (SecretKey) keyStore.getKey("PSK" , "654321".toCharArray());
		//SecretKey secretKey2 = (SecretKey) keyStore.getKey("PSK111" , "654321".toCharArray());
		//System.out.println(HexUtils.toHexString(secretKey1.getEncoded()));
		//System.out.println(HexUtils.toHexString(secretKey2.getEncoded()));

		String pwd = "43654297387968386849380867064969";
		byte[] bytes = HexUtils.fromHexString(pwd);
		SecretKey secretKey = new SecretKeySpec(bytes , "JKS");
		KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
		keyStore.setEntry("PSK" , entry, new KeyStore.PasswordProtection("654321".toCharArray()));


		FileOutputStream fileOutputStream = new FileOutputStream("src/main/resources/BipKeystore.jks");
		keyStore.store(fileOutputStream , "654321".toCharArray());

	}

	@Test
	public void get() throws Exception{
		List<String> list = new ArrayList<>();
		list.add("1");
		list.add("2");
		list.add("3");
		list.add("4");
		list.add("5");
		list.add("6");
		list.add("7");
		List<List<String>> result = Lists.partition(list , 3);
		//System.out.println("result  size = " + RamUsageEstimator.humanSizeOf(result));
		//System.out.println("list  size = " + RamUsageEstimator.humanSizeOf(list));
		result.get(0).clear();
		System.out.println(result.get(0));
		result.get(0).clear();
		System.out.println(result.get(0));


		//result.get().clear();
		//System.out.println("Profile list size = " + RamUsageEstimator.humanSizeOf(result));
		//System.out.println("list  size = " + RamUsageEstimator.humanSizeOf(list));
		//System.out.println(list.get(1));



	}

	@Test
	public void testExcel(){
		List<ProfileExcel> profileExcels = prepareData();

		String fileName = "indexWrite" + System.currentTimeMillis() + ".xlsx";
		EasyExcel.write(fileName, ProfileExcel.class).sheet("模板").doWrite(profileExcels);
	}

	private List<ProfileExcel> prepareData(){
	    List<ProfileExcel> result = new LinkedList<>();
	    int iccid = 100003098;
	    String iccidPrefix = "19886013137";
	    int imsi = 1300000309;
	    String imsiPrefix = "46601";
	    for(int i = 0 ; i < 100000 ; i ++){
	        iccid++;
	        String nowIccid = iccidPrefix + iccid;
	        imsi++;
	        String nowImsi = imsiPrefix + imsi;
	        byte[] kiBytes = new byte[16];
	        new Random(i).nextBytes(kiBytes);
            byte[] opcBytes = new byte[16];
            new Random(i+1000000).nextBytes(opcBytes);
	        String ki = HexUtils.toHexString(kiBytes);
	        String opc = HexUtils.toHexString(opcBytes);
	        ProfileExcel profileExcel = ProfileExcel.builder().iccid(nowIccid).imsi(nowImsi).ki(ki).opc(opc).build();
	        result.add(profileExcel);
        }
        return result;
	}
	@Test
	public void debug() throws Exception{
FileInputStream fileInputStream = new FileInputStream(eumertPath);
		X509Certificate EUM = (X509Certificate) factory.generateCertificate(fileInputStream);
		FileInputStream fileInputStream1 = new FileInputStream(euiccCertPath);
		X509Certificate EUICC = (X509Certificate) factory.generateCertificate(fileInputStream1);

		EUICC.verify(EUM.getPublicKey());


		System.out.println(checkEid("8902302200001000000aa00003645777"));

	}

	static Pattern p = Pattern.compile("^[0-9]{32}$");

	private static boolean checkEid(String s) {
		if (Strings.isNullOrEmpty(s)) {
			return false;
		}
		if (!p.matcher(s).matches()) {
			return false;
		}
		BigInteger eidNum = new BigInteger(s.substring(0, 30) + "00", 10);
		int lastTwoDigits = Integer.parseInt(s.substring(30));
		int calculatedDigits = 98 - eidNum.mod(new BigInteger("97", 10)).intValue();
		if (lastTwoDigits != calculatedDigits) {
			return false;
		}
		return true;
	}

	@Test
	public void convert(){
		String cert = "30819502010030140607\n" +
                "2A8648CE3D020106092B240303020801\n" +
                "0107047A3078020101042093BCF8A16F\n" +
                "9F196D47BC547DA1CA6C121323BB176D\n" +
                "C4B7BC239E680063496D06A00B06092B\n" +
                "2403030208010107A1440342000440AE\n" +
                "DFC4AD2D1D2EBFE54C2E39B5382903B1\n" +
                "64DF1938B8832F4924D0C91734659FA7\n" +
                "5DBC519DA139828234B520D307B0D412\n" +
                "A479F2CBBD86D14B12CCCF900D06";
		String s1 = Base64Utils.encodeToString(HexUtils.fromHexString(cert.replaceAll("\n","")));

		System.out.println(s1);
	}

	@Test
    public void testPattern(){
	    //Pattern pattern = Pattern.compile(".*0201010420.*");
	    String s = "0107047A3078020101042093BCF8A16F";
        System.out.println(s.indexOf("0201010420"));
        StringBuilder sb = new StringBuilder(s);
	    sb.replace(22 , 24 , "aa");
	    System.out.println(sb.toString());
    }

    @Test
	public void testBigInt(){
		byte[] big1 = HexUtils.fromHexString("008EA6B124759AB90B2DC3E9225205AF6D27A02E8E6F3F6DE94DBB18B0B7C15CA0");
		BigInteger bigInteger = new BigInteger(big1);
		System.out.println(bigInteger);
		BigInteger bigInteger1 = new BigInteger("64522943703623688299322792275300629955052761985844217145706287267364563147936");
		System.out.println(HexUtils.toHexString(bigInteger1.toByteArray()));
		byte[] big2 = HexUtils.fromHexString("4A244D1991DBD114328DB1728FCB1E08C658B9ECCEDD495DED514B7D88BE8D");
		BigInteger bigInteger2 = new BigInteger(big2);
		System.out.println(bigInteger2);
		BigInteger bigInteger3 = new BigInteger("130997224270788335042795292134084189586840170706884266830140417750338158221");
		System.out.println(HexUtils.toHexString(bigInteger3.toByteArray()));
	}


	@Test
    public void stringToOTA(){
List<String> list = new ArrayList<>();
	   list.add("1");
	   list.add("2");
	   List<String> list2 = new ArrayList<>(list);
	   list2.remove(1);
	   System.out.println(list);


	   //System.out.println("B000F1460F5254473030303237303535338944500703196198134F8683800382549300010202404201047523882360008222063F".toLowerCase());
byte[] bytes = HexUtils.fromHexString("B000F1460F5254473030303237303535338944500703196198134F8683800382549300010202404201047523882360008222063F");
		java.lang.String  s = new java.lang.String(bytes);

		s = "";
		testString(s);
		System.out.println(s);
    }

    private void testString(String s){
		s = "111";
	}


	@Test
    public void testKeyPair2() throws Exception{
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");

    }

	@Test
	public void testFeign() throws Exception{
	   /* byte[] bytes = new byte[16];
	    secureRandom.nextBytes(bytes);
	    System.out.println(HexUtils.toHexString(bytes));
	    ItoOSP(10, bytes);
        System.out.println(HexUtils.toHexString(bytes));*/


        //Calendar calendar = Calendar.getInstance();
        //calendar.setTime(new Date());
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        System.out.println(sdf.format(new Date()));
    }

    private static void ItoOSP(int i, byte[] sp)
    {
        sp[12] = (byte)(i >>> 24);
        sp[13] = (byte)(i >>> 16);
        sp[14] = (byte)(i >>> 8);
        sp[15] = (byte)(i >>> 0);
    }

}
