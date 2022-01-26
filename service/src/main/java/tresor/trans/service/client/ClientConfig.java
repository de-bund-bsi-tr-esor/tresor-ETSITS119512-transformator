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

import io.smallrye.config.ConfigMapping;
import java.time.Duration;
import java.util.Optional;


/**
 *
 * @author Florian Otto
 */
@ConfigMapping(prefix = "tresor.trans.client")
public interface ClientConfig {

	public Optional<TLSConfig> tlsConfig();

	public Optional<SamlEcpConfig> samlEcpConfig();

	public Optional<Integer> mtomThreshold();

	public Optional<String> schemaValidation();

	public static interface SamlEcpConfig {

		String tokenElement();

		String authnUrl();

		String ecpUrl();

		String acsUrl();

		String user();

		String pass();

		Duration tokenValidity();
	}

	public static interface TLSConfig {

		public String keystoreFilepath();

		public String keystoreSecret();

		public Optional<String> truststoreFilepath();

	}

}
