/****************************************************************************
 * Copyright (c) 2021 Federal Office for Information Security (BSI), ecsec GmbH
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

import de.bund.bsi.tr_esor.api._1_3.S4;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import org.apache.cxf.frontend.ClientProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Florian Otto
 */
@ApplicationScoped
public class S4ClientConfigurator {

	private final Logger LOG = LoggerFactory.getLogger(S4ClientConfigurator.class);

	@Inject
	ClientConfig config;

	public void configure(S4 client) throws TresorTransClientConfigException {

		var prox = ClientProxy.getClient(client);
		config.mtomThreshold().ifPresent(v -> {
			var db = prox.getEndpoint().getService().getDataBinding();
			db.setMtomThreshold(v);
			LOG.info("Setting MTOM threshold to: {}", db.getMtomThreshold());
		});

		//client schema validation
		prox.getRequestContext().put("schema-validation-enabled", config.schemaValidationOut().orElse(false));
		prox.getResponseContext().put("schema-validation-enabled", config.schemaValidationIn().orElse(false));
		prox.getRequestContext().forEach((k, v) -> LOG.debug("reqcontext: {} -> {} ", k, v));
		prox.getResponseContext().forEach((k, v) -> LOG.debug("respcontext: {} -> {} ", k, v));

		//authentication
		if (config.tlsConfig().isPresent()) {
			TLSProvisioning.configure(client, config.tlsConfig().get());
		} else if (config.samlEcpConfig().isPresent()) {
			SamlEcpProvisioning.configure(client, config.samlEcpConfig().get());
		}
	}

}
