package io.pivotal.mheath.credhubspike;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManagerFactory;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.FingerprintTrustManagerFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.credhub.core.CredHubProperties;
import org.springframework.credhub.core.ReactiveCredHubTemplate;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.http.client.HttpClient;

@SpringBootApplication
@EnableConfigurationProperties(ConfigProperties.class)
public class CredhubSpikeApplication {

	static {
		Provider bcProvider = new BouncyCastlePQCProvider();
		Security.addProvider(bcProvider);
	}

	final ConfigProperties properties;

	final CertificateIssuingService certificateIssuingService;

	@Value("${scs-credhub.certificate}") String certificate;

	@Autowired
	public CredhubSpikeApplication(ConfigProperties properties, CertificateIssuingService certificateIssuingService) {
		this.properties = properties;
		this.certificateIssuingService = certificateIssuingService;
	}

	@Bean
	@ScsCredhubQualifier
	HttpClient httpClient() {
		return HttpClient.create().secure(sslProviderBuilder ->
				sslProviderBuilder.sslContext(sslContext()));
	}

	@Bean
	@ScsCredhubQualifier
	TrustManagerFactory credhubTrustManagerFactory() {
		try {
			final X509CertificateHolder credhubCertificate = PemUtils.parseCertificate(certificate);
			return new FingerprintTrustManagerFactory(fingerPrint(credhubCertificate.getEncoded()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Bean
	@ConfigurationProperties(prefix = "scs-credhub")
	@ScsCredhubQualifier
	CredHubProperties credHubProperties() {
		return new CredHubProperties();
	}


	@Bean
	@ScsCredhubQualifier
	ReactiveCredHubTemplate reactiveCredHubTemplate() {
		return new ReactiveCredHubTemplate(credHubProperties(), new ReactorClientHttpConnector(httpClient()));
	}

	@Bean
	CommandLineRunner test() {
		return args -> reactiveCredHubTemplate().credentials().findByPath("/")
				.doOnNext(System.out::println)
				.blockLast();
	}

	private byte[] fingerPrint(byte[] message) {
		try {
			return MessageDigest.getInstance("SHA1").digest(message);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	private SslContext sslContext() {
		try {
			final JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(System.out));

			final KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
			rsa.initialize(2048);
			final KeyPair keyPair = rsa.generateKeyPair();
			pemWriter.writeObject(keyPair);
			pemWriter.flush();

			final X509Certificate certificate = certificateIssuingService.generateCertificate(keyPair, "048d3547-9a4a-405d-8f0e-8bd5e1858350");
			pemWriter.writeObject(certificate);
			pemWriter.flush();

			final X509CertificateHolder issuerCertificateHolder = PemUtils.parseCertificate(properties.getIssuer().getCertificate());
			final X509Certificate issuerCertificate = new JcaX509CertificateConverter().getCertificate(issuerCertificateHolder);

			return SslContextBuilder.forClient()
					.keyManager(keyPair.getPrivate(), certificate, issuerCertificate)
					.trustManager(credhubTrustManagerFactory())
					.build();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(CredhubSpikeApplication.class, args);
	}

}

