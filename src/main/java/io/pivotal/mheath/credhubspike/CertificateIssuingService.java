package io.pivotal.mheath.credhubspike;

import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Service;

/**
 *
 */
@Service
public class CertificateIssuingService {

	public static final String CERT_SIGNATURE_ALGORITHM = "SHA256WithRSA";

	final ConfigProperties properties;

	@Autowired
	public CertificateIssuingService(ConfigProperties properties) {
		this.properties = properties;
	}

	public X509Certificate generateCertificate(KeyPair keyPair, String uuid) throws Exception {
		final Instant now = Instant.now();
		final Instant expiration = now.plus(365, ChronoUnit.DAYS);
		final X509CertificateHolder issuingCertificate = PemUtils.parseCertificate(properties.getIssuer().getCertificate());
		final X500Name subject = new X500Name("OU=app:" + uuid + ", CN=" + UUID.randomUUID());
		final X500Name issuerDn = issuingCertificate.getSubject();
		final BigInteger certSerialNumber = new BigInteger(Long.toString(now.toEpochMilli()));

		final ContentSigner signer = new JcaContentSignerBuilder(CERT_SIGNATURE_ALGORITHM)
				.build(PemUtils.parsePrivateKey(properties.getIssuer().getPrivateKey()).getPrivate());

		final JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
				issuerDn,
				certSerialNumber,
				Date.from(now),
				Date.from(expiration),
				subject,
				keyPair.getPublic());

		final JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(issuingCertificate));
		certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		certificateBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

		return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
	}

	public static void main(String[] args) throws Exception {

		final SpringApplication springApplication = new SpringApplication(CertificateIssuingService.class);
		springApplication.setWebApplicationType(WebApplicationType.NONE);
		final ConfigurableApplicationContext context = springApplication.run(args);

		final JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(System.out));

		final KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		final KeyPair keyPair = rsa.generateKeyPair();
		pemWriter.writeObject(keyPair);
		pemWriter.flush();
		final X509Certificate certificate = context.getBean(CertificateIssuingService.class).generateCertificate(keyPair, "048d3547-9a4a-405d-8f0e-8bd5e1858350");
		pemWriter.writeObject(certificate);
		pemWriter.flush();
	}

}
