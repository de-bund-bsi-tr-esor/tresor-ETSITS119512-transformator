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

import java.util.Set;


/**
 *
 * @author Tobias Wich
 */
public class TypeConstants {

	public static final String ETSI_512_API_NS = "http://uri.etsi.org/19512/v1.1.2#";
	public static final String TRESOR_API_NS = "http://www.bsi.bund.de/tr-esor/api/1.3";
	public static final String TRESOR_VR_NS = "http://www.bsi.bund.de/tr-esor/vr/1.3";

	public static final String XAIP_TYPE = "http://www.bsi.bund.de/tr-esor/xaip/1.3";
	public static final String LXAIP_TYPE = "http://www.bsi.bund.de/tr-esor/lxaip/1.3";
	public static final String DXAIP_TYPE = "http://www.bsi.bund.de/tr-esor/dxaip/1.3";
	public static final String DLXAIP_TYPE = "http://www.bsi.bund.de/tr-esor/dlxaip/1.3";
	public static final String ASIC_TYPE = "http://uri.etsi.org/ades/ASiC/type/ASiC-ERS";
	public static final String CADES_TYPE = "http://uri.etsi.org/ades/CAdES";
	public static final String XADES_TYPE = "http://uri.etsi.org/ades/XAdES";
	public static final String PADES_TYPE = "http://uri.etsi.org/ades/PAdES";
	public static final String ASICE_TYPE = "http://uri.etsi.org/ades/ASiC/type/ASiC-E";
	public static final String ASICS_TYPE = "http://uri.etsi.org/ades/ASiC/type/ASiC-S";
	public static final String DIGESTLIST_TYPE = "http://uri.etsi.org/19512/format/DigestList";

	public static final String BINARYDATA_TYPE = "http://www.bsi.bund.de/tr-esor/api/1.3/type/binaryData";

	public static final String ERS_RFC_4998 = "urn:ietf:rfc:4998:EvidenceRecord";
	public static final String ERS_RFC_6283 = "urn:ietf:rfc:6283:EvidenceRecord";
	public static final String CADES_ERS = "http://uri.etsi.org/ades/CAdES/EvidenceRecord";

	public static final String S4_ERS_RFC_4998 = "urn:ietf:rfc:4998";
	public static final String S4_ERS_RFC_6283 = "urn:ietf:rfc:6283";

	public static final Set<String> SUPPORTED_XPATH_QUERY = Set.of("http://www.bsi.bund.de/tr-esor/api/1.3/query/xpath");

}
