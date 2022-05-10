import java.io.FileInputStream;
import java.security.PublicKey;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class XMLDigitalSignatureVerifier {

	private static Document getXMLDocument(String xmlFilePath) throws Exception {
		DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(true);
		return builderFactory.newDocumentBuilder().parse(new FileInputStream(xmlFilePath));
	}
	
	public static void main(String[] args) throws Exception {
		Document document = getXMLDocument("./signed.xml");
		NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		PublicKey publicKey = MyKeyPairGenerator.getPublicKey();
		DOMValidateContext domValidateContext = new DOMValidateContext(publicKey, nodeList.item(0));
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
		XMLSignature signature = factory.unmarshalXMLSignature(domValidateContext);
		if (signature.validate(domValidateContext)) {
			System.out.println("Khong bi chinh sua");
		} else {
			System.out.println("BI chinh sua");
		}
	}

}
