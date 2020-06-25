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

package tresor.trans.service;

import com.typesafe.config.Config;


/**
 *
 * @author Tobias Wich
 */
public class S4ClientConfig {

	private String type;
	private String endptUrl;
	private String profileFile;
	private boolean clientLogging;
	private boolean schemaValidationClient;
	private Config typeSpecific;

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getEndptUrl() {
		return endptUrl;
	}

	public void setEndptUrl(String endptUrl) {
		this.endptUrl = endptUrl;
	}

	public Config getTypeSpecific() {
		return typeSpecific;
	}

	public void setTypeSpecific(Config typeSpecific) {
		this.typeSpecific = typeSpecific;
	}

	public String getProfileFile() {
		return profileFile;
	}

	public void setProfileFile(String profileFile) {
		this.profileFile = profileFile;
	}

	public boolean isClientLogging() {
		return clientLogging;
	}

	public void setClientLogging(boolean clientLogging) {
		this.clientLogging = clientLogging;
	}

	public boolean isSchemaValidationClient() {
		return schemaValidationClient;
	}

	public void setSchemaValidationClient(boolean schemaValidationClient) {
		this.schemaValidationClient = schemaValidationClient;
	}

}
