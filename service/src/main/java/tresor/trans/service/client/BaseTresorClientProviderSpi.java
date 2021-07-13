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
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.SOAPBinding;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;


/**
 *
 * @author Tobias Wich
 */
public abstract class BaseTresorClientProviderSpi {

	protected S4ClientConfig conf;
	protected URL wsdlUrl;

	protected void init(S4ClientConfig conf) throws ClientConfigException {
		this.conf = conf;
	}

	public S4 buildService() {
		//S4_Service service = new S4_Service(wsdlUrl, new MTOMFeature(mtomThreshold));
		JaxWsProxyFactoryBean factory = buildFactory();
		S4 proxy = (S4) factory.create();

		// set some config any client wats to have
		baseConfig(proxy);
		// delegate configuration to the implementing class
		specificConfig(proxy);

		return proxy;
	}

	protected JaxWsProxyFactoryBean buildFactory() {
//		BusFactory bf = BusFactory.newInstance();
//		Bus b = bf.createBus();
		JaxWsProxyFactoryBean factory = new JaxWsProxyFactoryBean();
		//factory.setBus(b);
		factory.setServiceClass(S4.class);
		//factory.setAddress(wsdlUrl.toString());
		//factory.setWsdlURL(wsdlUrl.toString());

		var features = new ArrayList<>(Optional.ofNullable(factory.getFeatures()).orElse(List.of()));

		if (conf.isClientLogging()) {
			var logFeature = new LoggingFeature();
			logFeature.setLogMultipart(false);
			features.add(logFeature);
		}

		factory.setFeatures(features);

		return factory;
	}

	protected void baseConfig(S4 proxy) {
		BindingProvider bp = (BindingProvider) proxy;

		Map<String, Object> ctx = bp.getRequestContext();
		ctx.put("schema-validation-enabled", conf.isSchemaValidationClient());
		ctx.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, conf.getEndptUrl());

		SOAPBinding sb = (SOAPBinding) bp.getBinding();
		sb.setMTOMEnabled(conf.isClientMtom());

		Client cl = (Client) proxy;
		HTTPConduit http = (HTTPConduit) cl.getConduit();
		http.getClient().setAllowChunking(true);
	}

	protected abstract void specificConfig(S4 proxy);

}
