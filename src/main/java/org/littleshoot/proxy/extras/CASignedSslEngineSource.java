package org.littleshoot.proxy.extras;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLEngine;
import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Comparing with {@link SelfSignedSslEngineSource}, this class will accept a CA
 * private key and the certificate chain, and generate a certificate for the
 * given domain, then all the Mitm proxy generated certificates will be signed
 * by this CA, the benefit of doing this is that, the computer only need install
 * the CA certificate into its environment, then all the Mitm proxy generated
 * certificates will be trusted directly, as they are signed by the CA which is
 * already trusted.
 * 
 */
public class CASignedSslEngineSource extends BaseSelfSignedSslEngineSource {

	private static final Logger LOG = LoggerFactory.getLogger(CASignedSslEngineSource.class);

	private final String PASSWORD = "password";
	private final ReentrantLock lock = new ReentrantLock();

	private Key caPrivateKey;
	private Certificate[] caCertChain;
	private final String domain;
	private Certificate[] peerCerts;

	public CASignedSslEngineSource(String domain, Key caPrivateKey, Certificate[] caCertChain, Certificate[] peerCerts) {
		super(true);
		this.domain = domain;
		this.caPrivateKey = caPrivateKey;
		this.caCertChain = caCertChain;
		this.peerCerts = peerCerts;
	}

	@Override
	public SSLEngine newSslEngine() {
		try {
			lock.lock();
			try {
				if (getKeyStore() == null) {
					newKeyStore();
				} else {
					if (LOG.isDebugEnabled()) {
						LOG.debug("reuse existing keystore for domain " + domain);
					}
				}
			} finally {
				lock.unlock();
			}
			return getSslContext().createSSLEngine();
		} catch (Exception e) {
			throw new Error("Failed to initialize the server-side SSLContext", e);
		}
	}

	private void newKeyStore() throws Exception {
		KeyPair keyPair = newRSAKeyPair();
		PKCS10CertificationRequest csr = newCSR(keyPair);
		X509Certificate signedCertificate = signCSR(csr);
		// create keystore in memory
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		X500PrivateCredential intermediateCredential = new X500PrivateCredential(signedCertificate, keyPair.getPrivate(), domain);
		Certificate[] chain = new Certificate[caCertChain.length + 1];
		chain[0] = intermediateCredential.getCertificate();
		System.arraycopy(caCertChain, 0, chain, 1, caCertChain.length);
		keyStore.setKeyEntry(intermediateCredential.getAlias(), intermediateCredential.getPrivateKey(), PASSWORD.toCharArray(), chain);
		// use the generated keystore
		setKeyStore(keyStore, PASSWORD);
		LOG.info("generated new keystore for domain " + domain);
	}

	private X509Certificate signCSR(PKCS10CertificationRequest csr) throws IOException, OperatorCreationException, CertificateException,
			NoSuchProviderException {
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

		AsymmetricKeyParameter keyParameter = PrivateKeyFactory.createKey(caPrivateKey.getEncoded());

		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(X500Name.getInstance(((X509Certificate) caCertChain[0])
				.getSubjectX500Principal().getEncoded()), new BigInteger(32, new SecureRandom()), new Date(), DateUtils.addDays(new Date(),
				3 * 365), csr.getSubject(), csr.getSubjectPublicKeyInfo());

		certBuilder.addExtension(Extension.basicConstraints, true,
				new BasicConstraints(false));
		certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(
				KeyUsage.digitalSignature));
		copySubjectAlternativeName((X509Certificate) peerCerts[0], certBuilder);
		
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParameter);

		X509CertificateHolder holder = certBuilder.build(sigGen);
		org.bouncycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure();

		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
		X509Certificate signedCert = (X509Certificate) cf.generateCertificate(is1);
		is1.close();
		return signedCert;
	}
	
	private void copySubjectAlternativeName(X509Certificate src,
			X509v3CertificateBuilder dest) throws CertificateEncodingException, IOException {
		GeneralNames generalNames = GeneralNames.fromExtensions(
				new X509CertificateHolder(src.getEncoded()).getExtensions(),
				Extension.subjectAlternativeName);
		dest.addExtension(Extension.subjectAlternativeName, false, generalNames);
	}

	private PKCS10CertificationRequest newCSR(KeyPair keyPair) throws OperatorCreationException {
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + domain),
				keyPair.getPublic());
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer = csBuilder.build(keyPair.getPrivate());
		return p10Builder.build(signer);
	}

	private KeyPair newRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}
}
