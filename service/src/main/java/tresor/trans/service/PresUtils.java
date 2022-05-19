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

import de.bund.bsi.tr_esor.api._1.ArchiveDataResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveEvidenceResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveRetrievalResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveSubmissionResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveTraceResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveUpdateResponse;
import de.bund.bsi.tr_esor.api._1.ImportEvidenceType;
import de.bund.bsi.tr_esor.api._1.RequestType;
import de.bund.bsi.tr_esor.api._1.RetrieveInfoResponse;
import de.bund.bsi.tr_esor.api._1.XAIPDataType;
import de.bund.bsi.tr_esor.xaip.BinaryDataType;
import de.bund.bsi.tr_esor.xaip.DXAIPType;
import de.bund.bsi.tr_esor.xaip.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip.ObjectFactory;
import de.bund.bsi.tr_esor.xaip.XAIPType;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import javax.activation.DataHandler;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbException;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.UnmarshalException;
import javax.xml.namespace.QName;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.EvidenceRecordValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;
import org.etsi.uri._19512.v1_1.DeletionModeType;
import org.etsi.uri._19512.v1_1.EvidenceType;
import org.etsi.uri._19512.v1_1.POType;
import org.etsi.uri._19512.v1_1.ResponseType;
import org.etsi.uri._19512.v1_1.SearchResponseType;
import org.etsi.uri._19512.v1_1.SearchType;
import org.etsi.uri._19512.v1_1.SubjectOfRetrievalType;
import org.oasis_open.docs.dss_x.ns.base.AnyType;
import org.oasis_open.docs.dss_x.ns.base.InternationalStringType;
import org.oasis_open.docs.dss_x.ns.base.OptionalInputsType;
import org.oasis_open.docs.dss_x.ns.base.ResultType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import tresor.trans.service.client.ClientConfig;


/**
 *
 * @author Tobias Wich
 */
@ApplicationScoped
public class PresUtils {

	private class Lut<E> extends HashMap<String, E> {

		Lut with(String a, E b) {
			this.put(a, b);
			return this;
		}
	}

	private final Logger LOG = LoggerFactory.getLogger(PresUtils.class);

	@Inject
	ClientConfig clientConfig;

	JAXBContext preservePoJaxbCtx;
	Schema trsesorDataSchema;
	//minor mappings
	Map<String, String> tresorPresArchiveSubmissionMinorMapping;
	Map<String, String> tresorPresArchiveUpdateMinorMapping;
	Map<String, String> tresorPresArchiveRetrievalMinorMapping;
	Map<String, String> tresorPresArchiveEvidenceMinorMapping;
	Map<String, String> tresorPresArchiveDeletionMinorMapping;
	Map<String, String> tresorPresArchiveDataMinorMapping;
	Map<String, String> tresorPresVerifyMinorMapping;
	Map<String, String> tresorPresRetrieveInfoMinorMapping;
	Map<String, String> tresorPresRetrieveTraceMinorMapping;

	//major of minor mapping 
	//this can be used to change the preservation major result w.r.t. the minor result given by S4
	Map<String, ResultType.ResultMajor> tresorPresArchiveSubmissionMajorOfMinor = Collections.EMPTY_MAP;
	Map<String, ResultType.ResultMajor> tresorPresArchiveUpdateMajorOfMinor = Collections.EMPTY_MAP;
	Map<String, ResultType.ResultMajor> tresorPresArchiveRetrievalMajorOfMinor = Collections.EMPTY_MAP;
	Map<String, ResultType.ResultMajor> tresorPresArchiveEvidenceMajorOfMinor = Collections.EMPTY_MAP;
	Map<String, ResultType.ResultMajor> tresorPresArchiveDeletionMajorOfMinor = Collections.EMPTY_MAP;
	Map<String, ResultType.ResultMajor> tresorPresArchiveDataMajorOfMinor = Collections.EMPTY_MAP;
	Map<String, ResultType.ResultMajor> tresorPresVerifyMajorOfMinor = Collections.EMPTY_MAP;
	Map<String, ResultType.ResultMajor> tresorPresRetrieveInfoMajorOfMinor;
	Map<String, ResultType.ResultMajor> tresorPresRetrieveTraceMajorOfMinor = Collections.EMPTY_MAP;

	public PresUtils() throws JAXBException, SAXException {
		preservePoJaxbCtx = JAXBContext.newInstance(de.bund.bsi.tr_esor.api._1.ObjectFactory.class,
				org.etsi.uri._19512.v1_1.ObjectFactory.class,
				ReturnVerificationReport.class);

		var schemaFac = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		trsesorDataSchema = schemaFac.newSchema(getClass().getResource("/wsdl/tr-esor-interfaces-v1.3.xsd"));


		tresorPresArchiveDataMinorMapping = Collections.unmodifiableMap(new Lut()
				.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
				.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
				.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
				.with(TresorCodes.UNKNOWN_LOCATION, PresCodes.PARAM_ERROR)
				.with(TresorCodes.UNKNOWN_AOID, PresCodes.PARAM_ERROR)
				.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
		);

		tresorPresArchiveDeletionMinorMapping = Collections.unmodifiableMap(new Lut()
				.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
				.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
				.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
				.with(TresorCodes.MISSING_REASON_OF_DELETION, PresCodes.PARAM_ERROR)
				.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
				.with(TresorCodes.UNKNOWN_AOID, PresCodes.UNKNOWN_POID)
		);

		// ArchiveSubmission mapping
		tresorPresArchiveSubmissionMinorMapping = Collections.unmodifiableMap(new Lut()
				.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
				.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
				.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
				.with(TresorCodes.NO_SPACE_LEFT, PresCodes.NO_SPACE_LEFT)
				.with(TresorCodes.LOW_SPACE, PresCodes.LOW_SPACE)
				.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
				.with(TresorCodes.UNKNOWN_ARCHIVE_DATA_TYPE, PresCodes.UNKNOWN_PO_FORMAT)
				.with(TresorCodes.XAIP_NOK, PresCodes.PO_FORMAT_ERROR)
				.with(TresorCodes.XAIP_NOK_EXPIRED, PresCodes.PO_FORMAT_ERROR)
				.with(TresorCodes.XAIP_NOK_SUBMTIME, PresCodes.PO_FORMAT_ERROR)
				.with(TresorCodes.XAIP_NOK_SIG, PresCodes.PO_FORMAT_ERROR)
				.with(TresorCodes.XAIP_NOK_ER, PresCodes.PO_FORMAT_ERROR)
				.with(TresorCodes.EXISTING_AOID, PresCodes.EXISTING_POID)
		);

		// ArchiveSubmission mapping
		tresorPresArchiveUpdateMinorMapping = Collections.unmodifiableMap(new Lut()
				.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
				.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
				.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
				.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
				.with(TresorCodes.NO_SPACE_LEFT, PresCodes.NO_SPACE_LEFT)
				.with(TresorCodes.DXAIP_NOK_AOID, PresCodes.UNKNOWN_POID)
				.with(TresorCodes.EXISTING_PACKAGE_WARN, PresCodes.INT_ERROR_DELTA_POC)
				.with(TresorCodes.DXAIP_NOK, PresCodes.INT_ERROR_DELTA_POC)
				.with(TresorCodes.DXAIP_NOK_EXPIRED, PresCodes.INT_ERROR_DELTA_POC)
				.with(TresorCodes.DXAIP_NOK_SUBMTIME, PresCodes.INT_ERROR_DELTA_POC)
				.with(TresorCodes.DXAIP_NOK_SIG, PresCodes.INT_ERROR_DELTA_POC)
				.with(TresorCodes.XAIP_NOK_ER, PresCodes.PO_FORMAT_ERROR)
				.with(TresorCodes.DXAIP_NOK_ID, PresCodes.INT_ERROR_DELTA_POC)
				.with(TresorCodes.DXAIP_NOK_VERSION, PresCodes.INT_ERROR_DELTA_POC)
				.with(TresorCodes.LOW_SPACE, PresCodes.LOW_SPACE)
		);

		// ArchiveRetrieval mapping
		tresorPresArchiveRetrievalMinorMapping = Collections.unmodifiableMap(new Lut()
				.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
				.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
				.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
				.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
				.with(TresorCodes.UNKNOWN_PO_FORMAT, PresCodes.UNKNOWN_PO_FORMAT)
				.with(TresorCodes.UNKNOWN_AOID, PresCodes.UNKNOWN_POID)
				.with(TresorCodes.UNKNOWN_VERSION, PresCodes.UNKNOWN_VERSION)
				.with(TresorCodes.PARTLY_SUCCESSFUL, PresCodes.PARTLY_SUCCESSFUL)
		);

		// ArchiveEvidence mapping
		tresorPresArchiveEvidenceMinorMapping = Collections.unmodifiableMap(new Lut()
				.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
				.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
				.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
				.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
				.with(TresorCodes.UNKNOWN_AOID, PresCodes.UNKNOWN_POID)
				.with(TresorCodes.UNKNOWN_VERSION, PresCodes.UNKNOWN_VERSION)
				.with(TresorCodes.PARTLY_SUCCESSFUL, PresCodes.PARTLY_SUCCESSFUL)
		);

		// Verify mapping
		tresorPresVerifyMinorMapping = Collections.unmodifiableMap(new Lut()
				.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
				.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
				.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
				.with(TresorCodes.MISSING_REASON_OF_DELETION, PresCodes.PARAM_ERROR)
				.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
		);

		//RetrieveInfo mapping
		tresorPresRetrieveInfoMinorMapping = Collections.unmodifiableMap(new Lut()
			.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
			.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
			.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
			.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
		);

		tresorPresRetrieveInfoMajorOfMinor = Collections.unmodifiableMap(new Lut()
			.with(TresorCodes.PARAM_ERROR, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
			.with(TresorCodes.NOT_SUPPORTED, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
		);

		//RetrieveTrace mapping
		tresorPresRetrieveTraceMinorMapping = Collections.unmodifiableMap(new Lut()
			.with(TresorCodes.NO_PERMISSION, PresCodes.NO_PERMISSION)
			.with(TresorCodes.INT_ERROR, PresCodes.INT_ERROR)
			.with(TresorCodes.PARAM_ERROR, PresCodes.PARAM_ERROR)
			.with(TresorCodes.NOT_SUPPORTED, PresCodes.NOT_SUPPORTED)
			.with(TresorCodes.UNKNOWN_AOID, PresCodes.UNKNOWN_POID)
		);

		tresorPresRetrieveTraceMajorOfMinor = Collections.unmodifiableMap(new Lut()
			.with(TresorCodes.PARAM_ERROR, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
			.with(TresorCodes.NOT_SUPPORTED, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
			.with(TresorCodes.UNKNOWN_AOID, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
		);

	}

	public String assertPoid(String poid, ResponseType res) throws InputAssertionFailed {
		return Optional.ofNullable(poid)
				.orElseThrow(() -> {
					String msg = "No POID present.";
					res.setResult(ResultType.builder()
							.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
							.withResultMinor(PresCodes.PARAM_ERROR)
							.withResultMessage(makeMsg(msg))
							.build());
					return new InputAssertionFailed(msg);
				});
	}

	public POType assertOnePo(List<POType> pos, ResponseType res) throws InputAssertionFailed {
		if (pos.size() != 1) {
			String msg = "Not exactly one PO requested.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		} else {
			return pos.get(0);
		}
	}

	public POType assertOneDeltaPOC(List<POType> pos, ResponseType res) throws InputAssertionFailed {
		if (pos.size() != 1) {
			String msg = "Not exactly one DeltaPOC requested.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.NOT_SUPPORTED)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		} else {
			return pos.get(0);
		}
	}

	static class UnknownFormatMinorCode {

		private final String value;
		private UnknownFormatMinorCode(String v) {
			this.value = v;
		}
		public static UnknownFormatMinorCode from(String v) {
			return new UnknownFormatMinorCode(v);
		}
	}

	private String getFormatIdOrDefault(String formatId, String def) {
		return formatId != null ? formatId : def;
	}

	public void assertAdmissiblePreserveFormat(POType po, ResponseType res) throws InputAssertionFailed {
		assertAdmissibleFormatInt(po.getFormatId(), res,
				Set.of(TypeConstants.XAIP_TYPE, TypeConstants.LXAIP_TYPE, TypeConstants.ASIC_TYPE,
						TypeConstants.CADES_TYPE, TypeConstants.XADES_TYPE, TypeConstants.PADES_TYPE,
						TypeConstants.ASICE_TYPE, TypeConstants.ASICS_TYPE, TypeConstants.DIGESTLIST_TYPE),
				UnknownFormatMinorCode.from(PresCodes.UNKNOWN_PO_FORMAT));
	}

	public void assertAdmissibleValidateFormat(POType po, ResponseType res) throws InputAssertionFailed {
		assertAdmissibleFormatInt(po.getFormatId(), res,
				Set.of(TypeConstants.XAIP_TYPE, TypeConstants.LXAIP_TYPE, TypeConstants.ASIC_TYPE,
						TypeConstants.CADES_TYPE, TypeConstants.XADES_TYPE, TypeConstants.PADES_TYPE,
						TypeConstants.ASICE_TYPE, TypeConstants.ASICS_TYPE, TypeConstants.DIGESTLIST_TYPE),
				UnknownFormatMinorCode.from(PresCodes.UNKNOWN_PO_FORMAT));
	}

	public String assertAdmissibleFormat(POType po, ResponseType res) throws InputAssertionFailed {
		var fId = assertAdmissibleFormat(po.getFormatId(), res);
		po.setFormatId(fId);
		return fId;
	}

	public String assertAdmissibleFormat(String formatId, ResponseType res) throws InputAssertionFailed {
		var fId = getFormatIdOrDefault(formatId, TypeConstants.XAIP_TYPE);
		assertAdmissibleFormatInt(fId, res, Set.of(TypeConstants.XAIP_TYPE, TypeConstants.LXAIP_TYPE, TypeConstants.ASIC_TYPE), UnknownFormatMinorCode.from(PresCodes.UNKNOWN_PO_FORMAT));
		return fId;
	}

	public String assertAdmissibleFormat(EvidenceType po, ResponseType res) throws InputAssertionFailed {
		var evidenceFormat = po.getFormatId();
		var fId = getFormatIdOrDefault(evidenceFormat, TypeConstants.ERS_RFC_4998);
		assertAdmissibleFormatInt(fId, res, Set.of(TypeConstants.ERS_RFC_4998, TypeConstants.ERS_RFC_6283, TypeConstants.CADES_ERS), UnknownFormatMinorCode.from(PresCodes.UNKNOWN_PO_FORMAT));
		return fId;
	}

	public String assertRetrieveEvidenceFormat(String evidenceFormat, ResponseType res) throws InputAssertionFailed {
		var fId = getFormatIdOrDefault(evidenceFormat, TypeConstants.ERS_RFC_4998);
		assertAdmissibleFormatInt(fId, res, Set.of(TypeConstants.ERS_RFC_4998, TypeConstants.ERS_RFC_6283), UnknownFormatMinorCode.from(PresCodes.UNKNOWN_PO_FORMAT));
		return fId;
	}

	public String assertAdmissibleDeltaFormat(POType po, ResponseType res) throws InputAssertionFailed {
		var fId = getFormatIdOrDefault(po.getFormatId(), null);
		assertAdmissibleFormatInt(fId, res, Set.of(TypeConstants.DXAIP_TYPE, TypeConstants.DLXAIP_TYPE), UnknownFormatMinorCode.from(PresCodes.UNKNOWN_DELTA_POC_TYPE));
		return fId;
	}

	private void assertAdmissibleFormatInt(String formatId, ResponseType res, Set<String> allowedTypes, UnknownFormatMinorCode unknownFormatMinorCode) throws InputAssertionFailed {
		try {
			Optional.ofNullable(formatId)
					.filter(v -> allowedTypes.contains(v))
					.orElseThrow(() -> {
				String msg = String.format("Format (%s) is not one of the allowed types.", formatId);
						res.setResult(ResultType.builder()
								.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
								.withResultMinor(unknownFormatMinorCode.value)
								.withResultMessage(makeMsg(msg))
								.build());
						return new InputAssertionFailed(msg);
					});
		} catch (NullPointerException ex) {
			String msg = "Format is not defined.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}
	}

	public String convertToS4EvidenceFormat(String etsiEvidenceFormat) {
		switch (etsiEvidenceFormat) {
			case TypeConstants.ERS_RFC_4998:
				return TypeConstants.S4_ERS_RFC_4998;
			case TypeConstants.ERS_RFC_6283:
				return TypeConstants.S4_ERS_RFC_6283;
			default:
				return etsiEvidenceFormat;
		}
	}

	public boolean isVerificationReport(Object o) {
		return isWrappedType(o, VerificationReportType.class, new QName("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#", "VerificationReport"));
	}

	public boolean isXaip(POType po) {
		return isFormatIdType(po, TypeConstants.XAIP_TYPE, TypeConstants.LXAIP_TYPE);
	}

	public boolean isDXaip(POType po) {
		return isFormatIdType(po, TypeConstants.DXAIP_TYPE, TypeConstants.DLXAIP_TYPE);
	}

	public boolean isAsic(POType po) {
		return isFormatIdType(po, TypeConstants.ASIC_TYPE);
	}

	public boolean isErs(POType po) {
		return isFormatIdType(po, TypeConstants.ERS_RFC_4998, TypeConstants.ERS_RFC_6283);
	}

	public boolean isBinaryErs(POType po) {
		return isFormatIdType(po, TypeConstants.ERS_RFC_4998);
	}

	public boolean isXmlErs(POType po) {
		return isFormatIdType(po, TypeConstants.ERS_RFC_6283);
	}

	private boolean isFormatIdType(POType po, String... formats) {
		return Optional.ofNullable(po.getFormatId())
				.filter(v -> Set.of(formats).contains(v))
				.isPresent();
	}

	public XAIPType assertXaipPresent(POType po, ResponseType res) throws InputAssertionFailed {
		return assertSpecificTypePresentInt(po, res, XAIPType.class, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR);
	}

	public DXAIPType assertDXaipPresent(POType po, ResponseType res) throws InputAssertionFailed {
		return assertSpecificTypePresentInt(po, res, DXAIPType.class, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR);
	}

	public XAIPType assertReturnedXaipPresent(POType po, ResponseType res) throws OutputAssertionFailed {
		try {
			return assertSpecificTypePresentInt(po, res, XAIPType.class, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR);
		} catch (InputAssertionFailed ex) {
			throw new OutputAssertionFailed(ex.getMessage(), ex.getCause());
		}
	}

//	public JAXBElement<EvidenceRecordType> assertEvidenceRecordPresent(EvidenceType po, ResponseType res) throws InputAssertionFailed {
//		return assertSpecificWrappedTypePresentInt(po, res, EvidenceRecordType.class, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR);
//	}

	private <T> T assertSpecificTypePresentInt(POType po, ResponseType res, Class<T> targetClass, ResultType.ResultMajor majorError) throws InputAssertionFailed {
		return assertSpecificWrappedTypePresentInt(po, res, targetClass, majorError).getValue();
	}

	private <T> JAXBElement<T> assertSpecificWrappedTypePresentInt(POType po, ResponseType res, Class<T> targetClass, ResultType.ResultMajor majorError) throws InputAssertionFailed {
		Object targetObj = Optional.ofNullable(po.getXmlData())
				.map(xd -> xd.getAny())
				.orElseThrow(() -> {
					String msg = String.format("No %s data object present.", targetClass.getName());
					res.setResult(ResultType.builder()
							.withResultMajor(majorError)
							.withResultMinor(PresCodes.PARAM_ERROR)
							.withResultMessage(makeMsg(msg))
							.build());
					return new InputAssertionFailed(msg);
				});

		if (targetObj instanceof JAXBElement && ((JAXBElement) targetObj).getDeclaredType().isAssignableFrom(targetClass)) {
			var jbxaip = (JAXBElement<T>) targetObj;
			return jbxaip;
		} else {
			String msg = String.format("Data type is not a %s (actual: %s).", targetClass.getName(), targetObj.getClass().getName());
			res.setResult(ResultType.builder()
					.withResultMajor(majorError)
					.withResultMinor(PresCodes.PO_FORMAT_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}
	}

	public Object assertXmlPresent(POType po, ResponseType res) throws InputAssertionFailed {
		return Optional.ofNullable(po.getXmlData())
				.map(bd -> bd.getAny())
				.orElseThrow(() -> {
					String msg = "No XML data object present.";
					res.setResult(ResultType.builder()
							.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
							.withResultMinor(PresCodes.PARAM_ERROR)
							.withResultMessage(makeMsg(msg))
							.build());
					return new InputAssertionFailed(msg);
				});
	}

	public DataHandler assertBinaryPresent(POType po, ResponseType res) throws InputAssertionFailed {
		return Optional.ofNullable(po.getBinaryData())
				.map(bd -> bd.getValue())
				.orElseThrow(() -> {
					String msg = "No binary data object present.";
					res.setResult(ResultType.builder()
							.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
							.withResultMinor(PresCodes.PARAM_ERROR)
							.withResultMessage(makeMsg(msg))
							.build());
					return new InputAssertionFailed(msg);
				});
	}

	public JAXBElement<ietf.params.xml.ns.ers.EvidenceRecordType> assertXmlErsPresent(POType po, ResponseType res) throws InputAssertionFailed {
		return assertSpecificWrappedTypePresentInt(po, res, ietf.params.xml.ns.ers.EvidenceRecordType.class, ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR);
	}

	public InternationalStringType makeMsg(String msg) {
		return makeMsg(msg, "en");
	}

	public InternationalStringType makeMsg(String msg, String lang) {
		return InternationalStringType.builder()
				.withLang(lang)
				.withValue(msg)
				.build();
	}

	public void assertClientResultOk(RetrieveInfoResponse clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresRetrieveInfoMinorMapping, tresorPresRetrieveInfoMajorOfMinor);
	}

	public void assertClientResultOk(ArchiveTraceResponse clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresRetrieveTraceMinorMapping, tresorPresRetrieveTraceMajorOfMinor);
	}

	public void assertClientResultOk(ArchiveSubmissionResponse clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresArchiveSubmissionMinorMapping, tresorPresArchiveSubmissionMajorOfMinor);
	}

	public void assertClientResultOk(ArchiveUpdateResponse clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresArchiveUpdateMinorMapping, tresorPresArchiveUpdateMajorOfMinor);
	}

	public void assertClientResultOk(ArchiveRetrievalResponse clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresArchiveRetrievalMinorMapping, tresorPresArchiveRetrievalMajorOfMinor);
	}

	public void assertClientResultOk(ArchiveEvidenceResponse clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresArchiveEvidenceMinorMapping, tresorPresArchiveEvidenceMajorOfMinor);
	}

	public void assertClientResultDeletionOk(de.bund.bsi.tr_esor.api._1.ResponseType clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresArchiveDeletionMinorMapping, tresorPresArchiveDeletionMajorOfMinor);
	}

	public void assertClientResultVerifyOk(ResponseBaseType clientRes, ResponseType presRes) throws OutputAssertionFailed {
		assertClientResultOkInt(clientRes, presRes, tresorPresVerifyMinorMapping, tresorPresVerifyMajorOfMinor);
	}

	void assertClientResultOk(ArchiveDataResponse archRes, SearchResponseType res) throws OutputAssertionFailed {
		assertClientResultOkInt(archRes, res, tresorPresArchiveDataMinorMapping, tresorPresArchiveDataMajorOfMinor);
	}


	private void assertClientResultOkInt(ResponseBaseType clientRes, ResponseType presRes, Map<String, String> minorCodeMap, Map<String, ResultType.ResultMajor> majorOfMinor) throws OutputAssertionFailed {
		var result = Optional.of(clientRes.getResult())
				.filter(r -> r.isSetResultMajor())
				.orElseThrow(() -> {
					String msg = "No proper result received from TR-ESOR system.";
					presRes.setResult(ResultType.builder()
					    .withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					    .withResultMinor(PresCodes.INT_ERROR)
					    .withResultMessage(makeMsg(msg))
					    .build()
					);
					return new OutputAssertionFailed(msg);
				});

		if (Set.of(TresorCodes.OK, TresorCodes.WARN).contains(result.getResultMajor())) {
			if (TresorCodes.WARN.equals(result.getResultMajor())) {
				var resultMajor = ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS;

				if (result.getResultMinor().contains(TresorCodes.EXISTING_PACKAGE_WARN)) {
					resultMajor = ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR;
				}

				presRes.setResult(ResultType.builder()
					.withResultMajor(resultMajor)
					.withResultMinor(convertTresorMinor(result.getResultMinor(), minorCodeMap, true))
					.withResultMessage(convertMessage(result.getResultMessage()))
					.build());

			}
		} else if (TresorCodes.ERROR.equals(result.getResultMajor())) {
			var resultMajor = getMajorOfMinorOrDefault(majorOfMinor, result.getResultMinor(), ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR);
			presRes.setResult(ResultType.builder()
				.withResultMajor(resultMajor)
				.withResultMinor(convertTresorMinor(result.getResultMinor(), minorCodeMap, false))
				.withResultMessage(convertMessage(result.getResultMessage()))
				.build());
			throw new OutputAssertionFailed(Optional.ofNullable(result.getResultMessage())
					.map(v -> v.getValue())
					.orElse("Error received from TR-ESOR system."));
		} else {
			String msg = "No known resultmajor received from TR-ESOR system.";
			presRes.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new OutputAssertionFailed(msg);
		}
	}

	private ResultType.ResultMajor getMajorOfMinorOrDefault(Map<String, ResultType.ResultMajor> map, String minor, ResultType.ResultMajor defMajor) {
		return map.getOrDefault(minor, defMajor);
	}

	private String convertTresorMinor(String resultMinor, Map<String, String> codeMap, boolean nullAllowed) {
		return Optional.ofNullable(resultMinor)
				.map(code -> codeMap.getOrDefault(code, PresCodes.INT_ERROR))
				.orElseGet(() -> nullAllowed ? null : TresorCodes.INT_ERROR);
	}

	private InternationalStringType convertMessage(oasis.names.tc.dss._1_0.core.schema.InternationalStringType resultMessage) {
		return Optional.ofNullable(resultMessage)
				.map(v -> InternationalStringType.builder()
				.withLang(v.getLang())
				.withValue(v.getValue())
				.build())
				.orElse(null);
	}

	public Object convertPreservePoOptIn(AnyType psOptIn, ResponseType res) throws InputAssertionFailed {
		return getObjectIfTypeIsOneOf(psOptIn, res, List.of(
				o -> isWrappedType(o, String.class, new QName(TypeConstants.TRESOR_API_NS, "AOID")),
				o -> isWrappedType(o, ImportEvidenceType.class, new QName(TypeConstants.TRESOR_API_NS, "ImportEvidence")),
				o -> o instanceof ReturnVerificationReport
		));
	}

	public Object convertValidateEvidence(AnyType psOptIn, ResponseType res) throws InputAssertionFailed {
		return getObjectIfTypeIsOneOf(psOptIn, res, List.of(
				o -> isWrappedType(o, String.class, new QName(TypeConstants.TRESOR_API_NS, "VerifyUnderSignaturePolicy ")),
				o -> o instanceof ReturnVerificationReport
		));
	}

	public Object convertUpdatePocOptIn(AnyType psOptIn, ResponseType res) throws InputAssertionFailed {
		return getObjectIfTypeIsOneOf(psOptIn, res, List.of(
				o -> isWrappedType(o, ImportEvidenceType.class, new QName(TypeConstants.TRESOR_API_NS, "ImportEvidence")),
				o -> o instanceof ReturnVerificationReport
		));
	}

	/**
	 *
	 * @param optIn
	 * @param res
	 * @param typeChecks
	 * @return unmarshalled object if its type matches one of the given typeChecks
	 * @throws InputAssertionFailed if type does match none - additional res is altered by setting corresponding error
	 */
	private Object getObjectIfTypeIsOneOf(AnyType optIn, ResponseType res, List<Predicate<Object>> typeChecks) throws InputAssertionFailed {
		var binObj = Optional.ofNullable(optIn.getValue())
				.orElseThrow(() -> {
					String msg = "No binary data object present in optional input.";
					res.setResult(ResultType.builder()
							.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
							.withResultMinor(PresCodes.PARAM_ERROR)
							.withResultMessage(makeMsg(msg))
							.build());
					return new InputAssertionFailed(msg);
				});

		try {
			Object resultObj = preservePoJaxbCtx.createUnmarshaller().unmarshal(binObj.getInputStream());
			boolean matches = typeChecks.stream()
					.reduce((a, b) -> a.or(b))
					.map(p -> p.test(resultObj))
					.get();
			if (! matches) {
				// unsupported object
				String msg = "Unsupported optional input given.";
				res.setResult(ResultType.builder()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
						.withResultMinor(PresCodes.NOT_SUPPORTED)
						.withResultMessage(makeMsg(msg))
						.build());
				throw new InputAssertionFailed(msg);
			}

			return resultObj;
		} catch (UnmarshalException ex) {
			String msg = "Failed to unmarshal optional input.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.NOT_SUPPORTED)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		} catch (IOException | JAXBException ex) {
			String msg = "Failed to process optional input.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}
	}

	private boolean isWrappedType(Object o, Class<?> type, QName elemName) {
		if (o instanceof JAXBElement) {
			JAXBElement<?> jbElem = (JAXBElement<?>) o;
			boolean typeMatches = type.isAssignableFrom(jbElem.getDeclaredType());
			boolean nameMatches = elemName.equals(jbElem.getName());
			return typeMatches && nameMatches;
		}

		return false;
	}
	public oasis.names.tc.dss._1_0.core.schema.AnyType convertEvidenceRecord(DataHandler evRec, ResponseType res, String aoid, String vID) throws InputAssertionFailed {
		try {
			var er = new EvidenceRecordType();
			var readER = evRec.getInputStream().readAllBytes();
			er.setAsn1EvidenceRecord(readER);
			er.setAOID(aoid);
			er.setVersionID(vID);
			return oasis.names.tc.dss._1_0.core.schema.AnyType.builder()
				.withAny(new ObjectFactory().createEvidenceRecord(er))
				.build();
		} catch (IOException ex) {
			String msg = "Failed to read binary ERS.";
			LOG.error(msg, ex);
			res.setResult(ResultType.builder()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
				.withResultMinor(PresCodes.INT_ERROR)
				.withResultMessage(makeMsg(msg))
				.build());
			throw new InputAssertionFailed(msg);
		}
	}

	public oasis.names.tc.dss._1_0.core.schema.AnyType convertEvidenceRecord(ietf.params.xml.ns.ers.EvidenceRecordType evRec, ResponseType res, String aoid, String vID) throws InputAssertionFailed {
		var er = new EvidenceRecordType();
		er.setXmlEvidenceRecord(evRec);
		return oasis.names.tc.dss._1_0.core.schema.AnyType.builder()
				.withAny(new ObjectFactory().createEvidenceRecord(er))
				.build();
	}

	public Optional<AnyType> convertPreservePoOutput(Object tresorOptOut, ResponseType res) throws OutputAssertionFailed {
		try {
			if (isWrappedType(tresorOptOut, VerificationReportType.class, new QName("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#", "VerificationReport"))) {
				var ds = new TempFileDataSource(null);
				preservePoJaxbCtx.createMarshaller().marshal(tresorOptOut, ds.getOutputStream());
				ds.lock();
				return Optional.of(AnyType.builder().withValue(new DataHandler(ds)).build());
			} else {
				LOG.warn("Ignoring unsupported optional output from S4 service.");
				return Optional.empty();
			}
		} catch (UnmarshalException ex) {
			String msg = "Failed to marshal optional output.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new OutputAssertionFailed(msg);
		} catch (IOException | JAXBException ex) {
			String msg = "Failed to process optional output.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new OutputAssertionFailed(msg);
		}
	}

	public Optional<POType> convertValidateEvidenceOutput(Object tresorOptOut, ResponseType res) throws OutputAssertionFailed {
			if (isVerificationReport(tresorOptOut)) {
				var po = POType.builder()
						.withXmlData(POType.XmlData.builder()
								.withAny(tresorOptOut)
								.build())
						.build();
				return Optional.of(po);
			} else {
				LOG.warn("Ignoring unsupported optional output from S4 service.");
				return Optional.empty();
			}
	}

	public Optional<POType> convertRetrievePoOutput(Object tresorOptOut, ResponseType res) throws OutputAssertionFailed {
		if (isWrappedType(tresorOptOut, POType.class, new QName(TypeConstants.ETSI_512_API_NS, "PO"))) {
			var poElem = (JAXBElement<POType>) tresorOptOut;
			return Optional.of(poElem.getValue());
		} else {
			LOG.warn("Ignoring unsupported optional output from S4 service.");
			return Optional.empty();
		}
	}

	public Optional<OffsetDateTime> getProofOfExistence(VerificationReportType report) {
		return report.getIndividualReport().stream()
				.flatMap(ir -> ir.getDetails().getAny()
					.stream()
					.filter(o -> isWrappedType(o, EvidenceRecordValidityType.class, new QName(TypeConstants.TRESOR_VR_NS, "EvidenceRecordReport")))
					.map(o -> ((JAXBElement<EvidenceRecordValidityType>) o).getValue())
					.flatMap(erVal -> Optional.ofNullable(erVal.getArchiveTimeStampSequence()).stream()
						.flatMap(o -> o.getArchiveTimeStampChain().stream())
						.flatMap(ac -> ac.getArchiveTimeStamp()
							.stream()
							.flatMap(at -> Optional.ofNullable(at.getTimeStamp())
								.flatMap(o -> Optional.ofNullable(o.getTimeStampContent()))
								.flatMap(o -> Optional.ofNullable(o.getTstInfo()))
								.flatMap(o -> Optional.ofNullable(o.getCreationTime()))
								.stream()))))
				.sorted()
				.findFirst();
	}

	public void assertAoidMatches(DXAIPType dxaip, String aoid, ResponseType res) throws InputAssertionFailed {
		var xaipAoid = Optional.ofNullable(dxaip.getPackageHeader())
				.flatMap(v -> Optional.ofNullable(v.getAOID()))
				.orElseThrow(() -> {
					String msg = "No AOID present in XAIP.";
					res.setResult(ResultType.builder()
							.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
							.withResultMinor(PresCodes.PARAM_ERROR)
							.withResultMessage(makeMsg(msg))
							.build());
					return new InputAssertionFailed(msg);
				});

		if (!xaipAoid.equals(aoid)) {
			String msg = "Given AOID and AOID in XAIP differ.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR_DELTA_POC)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}
	}

	public SubjectOfRetrievalType assertSubjectOfRetrievalPoRetrieve(SubjectOfRetrievalType sr, ResponseType res) throws InputAssertionFailed {
		if (sr == null) {
			sr = SubjectOfRetrievalType.P_OWITH_EMBEDDED_EVIDENCE;
		}

		switch (sr) {
			case P_OWITH_DETACHED_EVIDENCE: {
				String msg = "Unsupported SubjectOfRetrieval received.";
				res.setResult(ResultType.builder()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
						.withResultMinor(PresCodes.NOT_SUPPORTED)
						.withResultMessage(makeMsg(msg))
						.build());
				throw new InputAssertionFailed(msg);
			}
			default:
				return sr;
		}
	}

	public void assertNoOptionalOutputs(oasis.names.tc.dss._1_0.core.schema.AnyType optionalOutputs, ResponseType res) throws OutputAssertionFailed {
		var vals = Optional.ofNullable(optionalOutputs)
				.map(oo -> oo.getAny())
				.orElseGet(() -> List.of());

		if (! vals.isEmpty()) {
			String msg = "Optional output values present where none are allowed.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.NOT_SUPPORTED)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new OutputAssertionFailed(msg);
		}
	}

	public void assertNoOptionalInputs(OptionalInputsType optIn, ResponseType res) throws InputAssertionFailed {
		var vals = Optional.ofNullable(optIn)
				.map(oo -> oo.getOther())
				.orElseGet(() -> List.of());

		if (! vals.isEmpty()) {
			String msg = "Optional input values present where none are allowed.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.NOT_SUPPORTED)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}
	}

	public void assertDeletionMode(DeletionModeType mode, ResponseType res) throws InputAssertionFailed {
		mode = Optional.ofNullable(mode)
				.orElse(DeletionModeType.SUB_D_OS_AND_EVIDENCE);

		if (mode != DeletionModeType.SUB_D_OS_AND_EVIDENCE) {
			String msg = "Invalid DeletionMode received.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.NOT_SUPPORTED)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}
	}

	public Object buildBinaryElement(Optional<String> mimeType, DataHandler binValue, ResponseType res) throws InputAssertionFailed {
		var binData = new BinaryDataType();
		mimeType.ifPresent(binData::setMimeType);
		binData.setValue(binValue);
		return new de.bund.bsi.tr_esor.xaip.ObjectFactory().createBinaryData(binData);
	}


	public SearchFilter assertAndConvertFilter(SearchType req, ResponseType res) throws InputAssertionFailed {
		if (false == req.isSetFilter()) {
			String msg = "Filter element missing";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}

		var filter = req.getFilter();
		Jsonb jb = JsonbBuilder.create();
		try {
			return jb.fromJson(filter, SearchFilter.class);
		} catch (JsonbException ex) {
			String msg = "Filter object not valid";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}

	}

	public AnyType convertXAIPData(XAIPDataType xaipData, ResponseType res) throws OutputAssertionFailed {
		try {
			var ds = new TempFileDataSource(null);
			var xaipDataObj = new de.bund.bsi.tr_esor.api._1.ObjectFactory().createXAIPData(xaipData);
			var m = preservePoJaxbCtx.createMarshaller();
			if (clientConfig.schemaValidation().isPresent()) {
				m.setSchema(trsesorDataSchema);
			}
			m.marshal(xaipDataObj, ds.getOutputStream());
			ds.lock();
			return AnyType.builder().withValue(new DataHandler(ds)).build();
		} catch (IOException | JAXBException ex) {
			String msg = "Failed to convert XPath object into DOM element.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new OutputAssertionFailed(msg);
		}
	}

	public void assertXaipDataPresent(ArchiveDataResponse archRes, SearchResponseType res) throws InputAssertionFailed {
		if (false == archRes.isSetXAIPData()) {
			String msg = "Failed to convert XPath object into DOM element.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}

	}

	public void filterDefaults(RequestType archReq) {
		archReq.getOptionalInputs().getAny()
			.removeIf(el -> {
			    if (isWrappedType(el, String.class, new QName(TypeConstants.ETSI_512_API_NS, "POFormat"))
					&& ((JAXBElement<String>) el).getValue().equals(TypeConstants.XAIP_TYPE)) {
					return true;
			    }
			    if (isWrappedType(el, String.class, new QName(TypeConstants.TRESOR_API_NS, "ERSFormat"))
					&& ((JAXBElement<String>) el).getValue().equals(TypeConstants.S4_ERS_RFC_4998)) {
					return true;
			    }
			    return false;
			});
	}

	public String mapFormat512ToS4(String formatId) {
		switch (formatId) {
			case TypeConstants.CADES_TYPE:
			case TypeConstants.XADES_TYPE:
			case TypeConstants.PADES_TYPE:
			case TypeConstants.ASICE_TYPE:
			case TypeConstants.ASICS_TYPE:
			case TypeConstants.DIGESTLIST_TYPE:
				return TypeConstants.BINARYDATA_TYPE;
			default:
				return formatId;
		}
	}

	public Optional<String> getDefaultMimeType(String formatId) {
		switch (formatId) {
			case TypeConstants.CADES_TYPE:
				return Optional.of("application/cms");
			case TypeConstants.XADES_TYPE:
				return Optional.of("application/xml");
			case TypeConstants.PADES_TYPE:
				return Optional.of("application/pdf");
			case TypeConstants.ASICE_TYPE:
				return Optional.of("application/vnd.etsi.asic-e+zip");
			case TypeConstants.ASICS_TYPE:
				return Optional.of("application/vnd.etsi.asic-s+zip");
			case TypeConstants.DIGESTLIST_TYPE:
				return Optional.of("application/xml");
			default:
				return Optional.empty();
		}
	}


	public boolean isXmlXadesOrDigestList(POType po, ResponseType res) {
		return po.isSetXmlData() &&
				(TypeConstants.XADES_TYPE.equals(po.getFormatId()) ||
				 TypeConstants.DIGESTLIST_TYPE.equals(po.getFormatId()));
	}

	public void convertXmlToBinary(POType po, ResponseType res) throws InputAssertionFailed {
		if (! (po.isSetXmlData() && po.getXmlData().isSetAny())) {
			String msg = "No XML data available in the PO.";
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.PARAM_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}

		try {
			var binData = new POType.BinaryData();
			Object xmlData = po.getXmlData().getAny();

			var tds = new TempFileDataSource(null);

			if (xmlData instanceof Element) {

				var tf = TransformerFactory.newInstance();
				tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
				var t = tf.newTransformer();

				var ds = new DOMSource((Element) xmlData);
				t.transform(ds, new StreamResult(tds.getOutputStream()));
				tds.lock();
			} else {
				var marshaller = preservePoJaxbCtx.createMarshaller();
				marshaller.marshal(xmlData, tds.getOutputStream());
				tds.lock();
			}

			//var sourceStream = new ByteArrayInputStream(sinkStream.toByteArray());
			var dh = new DataHandler(tds);
			binData.setValue(dh);

			// set binary and remove xml in exchange
			po.setBinaryData(binData);
			po.setXmlData(null);

		} catch (IOException ex) {
			String msg = "Error while processing serialized XML data.";
			LOG.error(msg, ex);
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		} catch (TransformerConfigurationException ex) {
			String msg = "Error creating the XML transformer.";
			LOG.error(msg, ex);
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		} catch (JAXBException | TransformerException ex) {
			String msg = "Error while serializing XML data.";
			LOG.error(msg, ex);
			res.setResult(ResultType.builder()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
					.withResultMessage(makeMsg(msg))
					.build());
			throw new InputAssertionFailed(msg);
		}

	}

}
