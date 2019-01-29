package io.pivotal.mheath.credhubspike;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 *
 */
public class PemUtils {

	public static X509CertificateHolder parseCertificate(String pemEncodedCertificate) {
		try {
			return (X509CertificateHolder) new PEMParser(new StringReader(pemEncodedCertificate)).readObject();
		} catch (
				IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static KeyPair parsePrivateKey(String pemEncodedPrivateKey) {
		try {
			final PEMKeyPair pemKeyPair = (PEMKeyPair) new PEMParser(new StringReader(pemEncodedPrivateKey)).readObject();
			return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private PemUtils() {}

}
