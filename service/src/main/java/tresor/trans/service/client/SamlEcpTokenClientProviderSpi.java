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

import tresor.trans.service.S4ClientConfig;
import de.bund.bsi.tr_esor.api._1_2.S4;
import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import org.apache.cxf.endpoint.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Tobias Wich
 */
@ApplicationScoped
@S4ClientProvider("ecp-token")
public class SamlEcpTokenClientProviderSpi extends BaseTresorClientProviderSpi {

	private final Logger LOG = LoggerFactory.getLogger(SamlEcpTokenClientProviderSpi.class);

	@Inject
	S4ClientConfig conf;

	@Inject
	SamlEcpTokenProvider tokProv;

	@PostConstruct
	void init() {
		super.init(conf);
	}

	@Override
	protected void specificConfig(S4 proxy) {
		Client cl = (Client) proxy;
		// obtain token and add token interceptor
		LOG.debug("Retrieving SAML-ECP auth token.");
		String authToken = tokProv.getToken();
		LOG.debug("Adding auth-token SOAP handler.");
		cl.getOutInterceptors().add(new SoapTokenAuthHandlerCxf(authToken));
	}

}
