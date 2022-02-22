

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

package tresor.trans.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Optional;
import java.util.logging.Level;
import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import org.etsi.uri._19512.v1_1.ObjectFactory;
import org.etsi.uri._19512.v1_1.ProfileType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Tobias Wich
 */
@ApplicationScoped
public class ProfileSupplier {

	private final Logger LOG = LoggerFactory.getLogger(ProfileSupplier.class);

	private JAXBContext ctx;
	private ProfileType profile;

	@Inject
	ApplicationConfig cfg;

	@PostConstruct
	void initJaxb() {
		try {
			var profileInputStream = new FileInputStream(new File(cfg.profileFilepath()));
			ctx = JAXBContext.newInstance(ObjectFactory.class);

			var unmarshaller = ctx.createUnmarshaller();
			JAXBElement<ProfileType> res = (JAXBElement<ProfileType>) unmarshaller.unmarshal(profileInputStream);
			profile = res.getValue();
		} catch (FileNotFoundException ex) {
			LOG.error("Configured 512-profile not found.");
			throw new RuntimeException("Failed to load profile.", ex);
		} catch (JAXBException ex) {
			LOG.error("Failed to load profile.", ex);
			throw new RuntimeException("Failed to load profile.", ex);
		}
	}

	public ProfileType getProfile() {
		return ProfileType.copyOf(profile).build();
	}

}
