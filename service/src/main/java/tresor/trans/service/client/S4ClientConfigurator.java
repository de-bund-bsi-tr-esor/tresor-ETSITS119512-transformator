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
import org.apache.cxf.annotations.SchemaValidation;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tresor.trans.service.ApplicationConfig;


/**
 *
 * @author Florian Otto
 */
@ApplicationScoped
public class S4ClientConfigurator {

	private final Logger LOG = LoggerFactory.getLogger(S4ClientConfigurator.class);

	@Inject
	ClientConfig clientConfig;
	@Inject
	ApplicationConfig appConfig;

	public void configure(S4 client) throws TresorTransClientConfigException {

		var prox = ClientProxy.getClient(client);

		configureMtom(prox);
		configureSchemaValidation(prox);
		configureAuthentication(client);

	}

	private void configureMtom(Client prox) {
		appConfig.mtomThreshold().ifPresent(v -> {
			var db = prox.getEndpoint().getService().getDataBinding();
			db.setMtomThreshold(v);
			LOG.info("Setting client MTOM threshold to: {}", db.getMtomThreshold());
		});
		appConfig.cacheDir().ifPresent(v -> {
			prox.getResponseContext().put("attachment-directory", v);
			LOG.info("Setting client MTOM directory to: {}", v);
		});

	}

	private void configureSchemaValidation(Client prox) {

		clientConfig.schemaValidation()
			.map(v -> v.toUpperCase())
			.map(v -> {
				switch (v) {
					case "TRUE":
						return "BOTH";
					case "FALSE":
						return "NONE";
					default:
						return v;
				}
			})
			.map(v -> SchemaValidation.SchemaValidationType.valueOf(v))
			.ifPresent(type -> {
				switch (type) {
					case OUT:
					case REQUEST:
					case BOTH:
						prox.getRequestContext().put("schema-validation-enabled", "true");
				}

				switch (type) {
					case IN:
					case RESPONSE:
					case BOTH:
						prox.getResponseContext().put("schema-validation-enabled", "true");
				}
			});

		prox.getRequestContext().forEach((k, v) -> LOG.debug("reqcontext option: {} -> {} ", k, v));
		prox.getResponseContext().forEach((k, v) -> LOG.debug("respcontext option: {} -> {} ", k, v));

	}

	private void configureAuthentication(S4 client) throws TresorTransClientConfigException {
		if (clientConfig.tlsConfig().isPresent()) {
			TLSProvisioning.configure(client, clientConfig.tlsConfig().get());
		} else if (clientConfig.samlEcpConfig().isPresent()) {
			SamlEcpProvisioning.configure(client, clientConfig.samlEcpConfig().get());
		}
	}


}
