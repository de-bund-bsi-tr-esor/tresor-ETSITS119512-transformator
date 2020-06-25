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


/**
 *
 * @author Tobias Wich
 */
public class TLSClientConfig {

	private String truststore;
	private String keystore;
	private String keystorePass;

	public String getTruststore() {
		return truststore;
	}

	public void setTruststore(String truststore) {
		this.truststore = truststore;
	}

	public String getKeystore() {
		return keystore;
	}

	public void setKeystore(String keystore) {
		this.keystore = keystore;
	}

	public String getKeystorePass() {
		return keystorePass;
	}

	public void setKeystorePass(String keystorePass) {
		this.keystorePass = keystorePass;
	}

}
