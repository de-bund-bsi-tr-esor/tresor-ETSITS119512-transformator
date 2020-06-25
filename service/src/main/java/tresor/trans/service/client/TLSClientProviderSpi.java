/****************************************************************************
 * Copyright (c) 2020 Federal Office for Information Security (BSI), ecsec GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

package tresor.trans.service.client;

import com.typesafe.config.ConfigBeanFactory;
import tresor.trans.service.S4ClientConfig;
import de.bund.bsi.tr_esor.api._1_2.S4;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.ws.BindingProvider;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.transport.http.HTTPConduit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Tobias Wich
 */
@S4ClientProvider("tls")
public class TLSClientProviderSpi extends BaseTresorClientProviderSpi {

	private final Logger LOG = LoggerFactory.getLogger(TLSClientProviderSpi.class);

	@Inject
	S4ClientConfig conf;

	private TLSClientConfig tlsConf;

	@PostConstruct
	void init() {
		super.init(conf);
		tlsConf = ConfigBeanFactory.create(conf.getTypeSpecific(), TLSClientConfig.class);
	}

	@Override
	protected void specificConfig(S4 proxy) {
		try {
			Client cl = (Client) proxy;
			HTTPConduit http = (HTTPConduit) cl.getConduit();
			TLSClientParameters tls = new TLSClientParameters();
			tls.setKeyManagers(createKeyManager(tlsConf));
			tls.setTrustManagers(createTrustManager(tlsConf));
			http.setTlsClientParameters(tls);

			Map<String, Object> ctx = ((BindingProvider) proxy).getRequestContext();
			ctx.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, conf.getEndptUrl());

		} catch (Exception ex) {
			LOG.error("Failed to configure S4 client.", ex);
			throw new RuntimeException("Failed to configure S4 client.", ex);
		}
	}

	private static KeyManager[] createKeyManager(TLSClientConfig cfg) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException {
		var kf = KeyManagerFactory.getInstance("PKIX");

		var ksFile = new File(cfg.getKeystore());
		var ks = KeyStore.getInstance(ksFile, (char[]) null);
		kf.init(ks, cfg.getKeystorePass().toCharArray());

		return kf.getKeyManagers();
	}

	private static TrustManager[] createTrustManager(TLSClientConfig cfg) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		var tf = TrustManagerFactory.getInstance("PKIX");

		var ksFile = new File(cfg.getTruststore());
		var ks = KeyStore.getInstance(ksFile, (char[]) null);
		tf.init(ks);

		return tf.getTrustManagers();
	}

}
