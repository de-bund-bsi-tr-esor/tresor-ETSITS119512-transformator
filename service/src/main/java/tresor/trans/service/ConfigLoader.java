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
import com.typesafe.config.ConfigBeanFactory;
import com.typesafe.config.ConfigFactory;
import java.io.File;
import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Tobias Wich
 */
@ApplicationScoped
public class ConfigLoader {

	private final Logger LOG = LoggerFactory.getLogger(ConfigLoader.class);

	private Config config;
	private S4ClientConfig s4ClientCfg;

	@PostConstruct
	void init() {
		LOG.info("Loading TR-ESOR Transformator configuration.");
		// load config from disc
		LOG.debug("Loading user config from home directory.");
		var homeCfgFile = getConfigFile();
		var userCfg = ConfigFactory.parseFile(homeCfgFile);
		// merge with bundled values
		config = ConfigFactory.load(userCfg);

		// create bean to access the values
		LOG.debug("Converting config to java bean.");
		s4ClientCfg = ConfigBeanFactory.create(config, S4ClientConfig.class);
	}

	File getConfigFile() {
		var home = new File(System.getProperty("user.home"));
		var cfgFile = new File(new File(home, ".tr-esor-transformator"), "application.conf");
		return cfgFile;
	}

	@Produces
	S4ClientConfig getConfig() {
		return s4ClientCfg;
	}

}
