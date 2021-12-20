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

import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.headers.Header;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.jaxb.JAXBDataBinding;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Tobias Wich
 */
public class SoapTokenAuthHandlerCxf extends AbstractPhaseInterceptor<SoapMessage> {

	private final Logger LOG = LoggerFactory.getLogger(SoapTokenAuthHandlerCxf.class);

	private SamlEcpTokenProvider ecpTokenProv;
	private final QName tokenHeaderName;

	public SoapTokenAuthHandlerCxf(ClientConfig.ProcilonConfig config) {
		super(Phase.PRE_PROTOCOL);
		this.tokenHeaderName = new QName(config.tokenHeaderName(), "IdentityToken");
		this.ecpTokenProv = new SamlEcpTokenProvider(config);
	}

	@Override
    public void handleMessage(SoapMessage m) throws Fault {
        try {
			SoapTokenAuthHeader myheader = new SoapTokenAuthHeader();
			myheader.setToken(ecpTokenProv.getToken());
			Header header = new Header(tokenHeaderName, myheader, new JAXBDataBinding(SoapTokenAuthHeader.class));
            m.getHeaders().add(header);
        } catch (JAXBException ex) {
			LOG.error("Failed to create JAXB Binding.", ex);
            throw new Fault(ex);
        }
    }

}
