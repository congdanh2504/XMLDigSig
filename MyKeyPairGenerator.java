import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class MyKeyPairGenerator {
	
	public static void main(String[] args) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		
		KeyPair keyPair = generator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		
		PrivateKey privateKey = keyPair.getPrivate();
		
		File publicKeyFile = createKeyFile(new File("./publicKey.key"));
		File privateKeyFile = createKeyFile(new File("./privateKey.key"));
		
		FileOutputStream fileOutputStream = new FileOutputStream(publicKeyFile);
		fileOutputStream.write(publicKey.getEncoded());
		fileOutputStream.close();
		
		fileOutputStream = new FileOutputStream(privateKeyFile);
		fileOutputStream.write(privateKey.getEncoded());
		fileOutputStream.close();
	}
	
	private static File createKeyFile(File file) throws IOException {
		if (file.exists()) file.delete();
		file.createNewFile();
		return file;
	}
	
	public static PublicKey getPublicKey() throws Exception {
		FileInputStream fileInputStream = new FileInputStream("./publicKey.key");
		byte [] b = new byte[fileInputStream.available()];
		
		fileInputStream.read(b);
		fileInputStream.close();
		
		X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(b);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePublic(encodedKeySpec);
	}
	
	public static PrivateKey getPrivateKey() throws Exception {
		FileInputStream fileInputStream = new FileInputStream("./privateKey.key");
		byte [] b = new byte[fileInputStream.available()];
		
		fileInputStream.read(b);
		fileInputStream.close();
		
		PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(b);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePrivate(encodedKeySpec);
	}
}
