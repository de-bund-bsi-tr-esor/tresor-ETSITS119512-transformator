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

import java.time.Duration;


/**
 *
 * @author Tobias Wich
 */
public class SamlEcpTokenConfig {

	private String authnUrl;
	private String ecpUrl;
	private String acsUrl;

	private String user;
	private String pass;

	private Duration tokenValidity;

	public String getAuthnUrl() {
		return authnUrl;
	}

	public void setAuthnUrl(String authnUrl) {
		this.authnUrl = authnUrl;
	}

	public String getEcpUrl() {
		return ecpUrl;
	}

	public void setEcpUrl(String ecpUrl) {
		this.ecpUrl = ecpUrl;
	}

	public String getAcsUrl() {
		return acsUrl;
	}

	public void setAcsUrl(String acsUrl) {
		this.acsUrl = acsUrl;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getPass() {
		return pass;
	}

	public void setPass(String pass) {
		this.pass = pass;
	}

	public Duration getTokenValidity() {
		return tokenValidity;
	}

	public void setTokenValidity(Duration tokenValidity) {
		this.tokenValidity = tokenValidity;
	}

}
