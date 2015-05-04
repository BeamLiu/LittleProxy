package org.littleshoot.proxy.extras;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Arrays;

import javax.net.ssl.SSLContext;

import org.apache.commons.io.IOUtils;
import org.littleshoot.proxy.SslEngineSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic {@link SslEngineSource} for testing. The {@link SSLContext} uses
 * self-signed certificates that are generated lazily if the given key store
 * file doesn't yet exist.
 */
public class SelfSignedSslEngineSource extends BaseSelfSignedSslEngineSource {
	private static final Logger LOG = LoggerFactory.getLogger(SelfSignedSslEngineSource.class);

	private static final String ALIAS = "littleproxy";
	private static final String PASSWORD = "Be Your Own Lantern";

	private final File keyStoreFile;

	public SelfSignedSslEngineSource(String keyStorePath, boolean trustAllServers, boolean sendCerts) {
		// no trust store specified, default to trust all
		super(sendCerts);
		this.keyStoreFile = new File(keyStorePath);
		initializeKeyStore();
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(keyStorePath), PASSWORD.toCharArray());
			setKeyStore(keyStore, PASSWORD);
		} catch (final Exception e) {
			throw new Error("Failed to initialize the server-side SSLContext", e);
		}
	}

	public SelfSignedSslEngineSource(String keyStorePath) {
		this(keyStorePath, false, true);
	}

	public SelfSignedSslEngineSource(boolean trustAllServers) {
		this(trustAllServers, true);
	}

	public SelfSignedSslEngineSource(boolean trustAllServers, boolean sendCerts) {
		this("littleproxy_keystore.jks", trustAllServers, sendCerts);
	}

	public SelfSignedSslEngineSource() {
		this(false);
	}

	private void initializeKeyStore() {
		if (keyStoreFile.isFile()) {
			LOG.info("Not deleting keystore");
			return;
		}

		nativeCall("keytool", "-genkey", "-alias", ALIAS, "-keysize", "4096", "-validity", "36500", "-keyalg", "RSA", "-dname",
				"CN=littleproxy", "-keypass", PASSWORD, "-storepass", PASSWORD, "-keystore", keyStoreFile.getName());

		nativeCall("keytool", "-exportcert", "-alias", ALIAS, "-keystore", keyStoreFile.getName(), "-storepass", PASSWORD, "-file",
				"littleproxy_cert");
	}

	private String nativeCall(final String... commands) {
		LOG.info("Running '{}'", Arrays.asList(commands));
		final ProcessBuilder pb = new ProcessBuilder(commands);
		try {
			final Process process = pb.start();
			final InputStream is = process.getInputStream();
			final String data = IOUtils.toString(is);
			LOG.info("Completed native call: '{}'\nResponse: '" + data + "'", Arrays.asList(commands));
			return data;
		} catch (final IOException e) {
			LOG.error("Error running commands: " + Arrays.asList(commands), e);
			return "";
		}
	}
}
