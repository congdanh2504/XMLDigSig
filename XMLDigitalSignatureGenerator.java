import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

public class XMLDigitalSignatureGenerator {
	
	private static Document getXMLDocument(String xmlFilePath) throws Exception {
		DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(true);
		return builderFactory.newDocumentBuilder().parse(new FileInputStream(xmlFilePath));
	}
	
	private static KeyInfo getKeyInfo(XMLSignatureFactory factory) throws Exception {
		PublicKey publicKey = MyKeyPairGenerator.getPublicKey();
		KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
		KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
		return keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));
	}
	
	private static void storeSignedDoc(Document doc, String desSignedXmlFilePath) throws Exception {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		StreamResult streamResult = new StreamResult(new File(desSignedXmlFilePath));
		transformer.transform(new DOMSource(doc), streamResult);
		System.out.println("Thanh cong");
	}

	public static void main(String[] args) throws Exception {
		Document document = getXMLDocument("./student.xml");
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
		PrivateKey privateKey = MyKeyPairGenerator.getPrivateKey();
		DOMSignContext domSignContext = new DOMSignContext(privateKey, document.getDocumentElement());
		
		Reference reference = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA1, null), 
				Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
		
		SignedInfo signedInfo = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (
				C14NMethodParameterSpec) null), 
				factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null), 
				Collections.singletonList(reference));
		
		KeyInfo keyInfo = getKeyInfo(factory);
		
		XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
		signature.sign(domSignContext);
		
		storeSignedDoc(document, "./signed.xml");
	}

}
