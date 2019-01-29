package io.pivotal.mheath.credhubspike;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 *
 */
@ConfigurationProperties
public class ConfigProperties {

	private Certificate issuer;

	public static class Certificate {
		private String ca;
		private String certificate;
		private String privateKey;

		public String getCa() {
			return ca;
		}

		public void setCa(String ca) {
			this.ca = ca;
		}

		public String getCertificate() {
			return certificate;
		}

		public void setCertificate(String certificate) {
			this.certificate = certificate;
		}

		public String getPrivateKey() {
			return privateKey;
		}

		public void setPrivateKey(String privateKey) {
			this.privateKey = privateKey;
		}
	}

	public Certificate getIssuer() {
		return issuer;
	}

	public void setIssuer(Certificate issuer) {
		this.issuer = issuer;
	}
}
