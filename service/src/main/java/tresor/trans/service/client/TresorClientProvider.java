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

import de.bund.bsi.tr_esor.api._1_2.S4;
import java.lang.annotation.Annotation;
import javax.annotation.PostConstruct;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.enterprise.util.AnnotationLiteral;
import javax.inject.Inject;
import tresor.trans.service.S4ClientConfig;


/**
 *
 * @author Tobias Wich
 */
public class TresorClientProvider {

	private Annotation providerType;

	@Inject
	@Any
	Instance<BaseTresorClientProviderSpi> s4Prov;

	@Inject
	S4ClientConfig conf;

	private static class S4ClientProviderLiteral extends AnnotationLiteral<S4ClientProvider> implements S4ClientProvider {
		String type;
		S4ClientProviderLiteral(String type) {
			this.type = type;
		}

		@Override
		public String value() {
			return type;
		}
	}

	@PostConstruct
	void init() {
		// read type from config
		String type = conf.getType();
		providerType = new S4ClientProviderLiteral(type);
	}

	@Produces
	S4 getInstance() {
		BaseTresorClientProviderSpi prov = s4Prov.select(providerType).get();
		S4 proxy = prov.buildService();
		return proxy;
	}

}
