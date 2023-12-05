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

import de.bund.bsi.tr_esor.api._1.ArchiveDataRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveDataType;
import de.bund.bsi.tr_esor.api._1.ArchiveDeletionRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveEvidenceRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveRetrievalRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveSubmissionRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveTraceRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveUpdateRequest;
import de.bund.bsi.tr_esor.api._1.DataLocation;
import de.bund.bsi.tr_esor.api._1.ObjectFactory;
import de.bund.bsi.tr_esor.api._1.ReasonOfDeletion;
import de.bund.bsi.tr_esor.api._1.RetrieveInfoRequest;
import de.bund.bsi.tr_esor.api._1_3.S4;
import io.quarkiverse.cxf.annotation.CXFClient;
import io.quarkus.runtime.configuration.ConfigurationException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import jakarta.jws.WebService;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.ws.soap.SOAPFaultException;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.Base64Data;
import oasis.names.tc.dss._1_0.core.schema.Base64Signature;
import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.InlineXMLType;
import oasis.names.tc.dss._1_0.core.schema.InputDocuments;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;
import oasis.names.tc.saml._2_0.assertion.NameIDType;
import org.apache.cxf.annotations.EndpointProperties;
import org.apache.cxf.annotations.EndpointProperty;
import org.etsi.uri._19512.v1_1.DeletePOType;
import org.etsi.uri._19512.v1_1.POType;
import org.etsi.uri._19512.v1_1.PreservePOResponseType;
import org.etsi.uri._19512.v1_1.PreservePOType;
import org.etsi.uri._19512.v1_1.ProfileType;
import org.etsi.uri._19512.v1_1.ResponseType;
import org.etsi.uri._19512.v1_1.RetrieveInfoResponseType;
import org.etsi.uri._19512.v1_1.RetrieveInfoType;
import org.etsi.uri._19512.v1_1.RetrievePOResponseType;
import org.etsi.uri._19512.v1_1.RetrievePOType;
import org.etsi.uri._19512.v1_1.RetrieveTraceResponseType;
import org.etsi.uri._19512.v1_1.RetrieveTraceType;
import org.etsi.uri._19512.v1_1.SearchResponseType;
import org.etsi.uri._19512.v1_1.SearchType;
import org.etsi.uri._19512.v1_1.StatusType;
import org.etsi.uri._19512.v1_1.SubjectOfRetrievalType;
import org.etsi.uri._19512.v1_1.TraceType;
import org.etsi.uri._19512.v1_1.UpdatePOCResponseType;
import org.etsi.uri._19512.v1_1.UpdatePOCType;
import org.etsi.uri._19512.v1_1.ValidateEvidenceResponseType;
import org.etsi.uri._19512.v1_1.ValidateEvidenceType;
import org.etsi.uri._19512.v1_1_2_.Preservation;
import org.oasis_open.docs.dss_x.ns.base.OptionalOutputsType;
import org.oasis_open.docs.dss_x.ns.base.ResultType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tresor.trans.service.client.S4ClientConfigurator;
import tresor.trans.service.client.TresorTransClientConfigException;
import tresor.trans.service.endpointConfig.AttachementDirectoryConfigValue;
import tresor.trans.service.endpointConfig.AttachementMTOMEnabledValue;
import tresor.trans.service.endpointConfig.AttachementMemoryThresholdConfigValue;
import tresor.trans.service.endpointConfig.SchemaValidationConfigValue;


/**
 *
 * @author Tobias Wich
 */
@WebService(serviceName = "Preservation", portName = "Preservation", targetNamespace = "http://uri.etsi.org/19512/v1.1.2#", endpointInterface = "org.etsi.uri._19512.v1_1_2_.Preservation")
@EndpointProperties({
	@EndpointProperty(key = "schema-validation-enabled", beanClass = SchemaValidationConfigValue.class),
	@EndpointProperty(key = "attachment-directory", beanClass = AttachementDirectoryConfigValue.class),
	@EndpointProperty(key = "attachment-memory-threshold", beanClass = AttachementMemoryThresholdConfigValue.class),
	@EndpointProperty(key = "mtom-enabled", beanClass = AttachementMTOMEnabledValue.class)
})
public class PreservationService implements Preservation {

	private final Logger LOG = LoggerFactory.getLogger(PreservationService.class);

	@Inject
	@CXFClient("s4Client")
	S4 client;

	@Inject
	S4ClientConfigurator clientConfigurator;

	@PostConstruct
	void configureClient() throws TresorTransClientConfigException {
		clientConfigurator.configure(client);
	}
	@PostConstruct
	void assureProfileConfigured() throws ConfigurationException {
		try {
			profileSupplier.getProfile();
		} catch (Exception e) {
			throw new ConfigurationException("Profile could not be loaded. Stopping.");
		}
	}

	@Inject
	PresUtils utils;

	@Inject
	ProfileSupplier profileSupplier;

	@Override
	public RetrieveInfoResponseType retrieveInfo(RetrieveInfoType req) {
		LOG.debug("RetrieveInfo called.");

		var res = new RetrieveInfoResponseType();
		res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		List<ProfileType> profiles = new ArrayList<ProfileType>();

		var reqStatus = Optional.ofNullable(req.getStatus()).orElse(StatusType.ACTIVE);
		if (reqStatus == StatusType.INACTIVE || reqStatus == StatusType.ALL) {
			// nothing to add currently
		}
		if (reqStatus == StatusType.ACTIVE || reqStatus == StatusType.ALL) {
			profiles.add(profileSupplier.getProfile());
		}

		//filter for requested
		if (req.getProfile() != null) {
			profiles = profiles.stream()
				.filter(p -> p.getProfileIdentifier().equals(req.getProfile().strip()))
				.collect(Collectors.toList());
		}
		//if non left
		if (profiles.isEmpty()) {
			res = new RetrieveInfoResponseType();
			res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
				.withResultMinor(PresCodes.NOT_SUPPORTED)
			);
			res.setRequestID(req.getRequestID());

		}
		res.getProfile().addAll(profiles);

		LOG.debug("RetrieveInfo finished.");
		return res;
	}


	@Override
	public PreservePOResponseType preservePO(PreservePOType req) {
		LOG.debug("PreservePO called.");
		var res = new PreservePOResponseType();
		res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		try {
			//check profile
			if (req.getProfile() != null && !req.getProfile().equals(profileSupplier.getProfileIdentifier())) {
				res.setResult(new ResultType()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
					.withResultMinor(PresCodes.NOT_SUPPORTED)
				);
				res.setRequestID(req.getRequestID());
				return res;
			}

			// exactly one PO
			POType po = utils.assertOnePo(req.getPO(), res);
			utils.assertAdmissiblePreserveFormat(po, res);

			var archReq = new ArchiveSubmissionRequest();
			archReq.setRequestID(req.getRequestID());

			if (utils.isXaip(po)) {
				var xaip = utils.assertXaipPresent(po, res);
				archReq.setXAIP(xaip);
			} else {
				if (utils.isXmlXadesOrDigestList(po, res)) {
					// convert XML to binary
					utils.convertXmlToBinary(po, res);
				}

				utils.assertBinaryPresent(po, res);

				var poFormatId = po.getFormatId();
				var s4FormatId = utils.mapFormat512ToS4(poFormatId);
				var s4MimeType = Optional.ofNullable(po.getMimeType())
						.or(() -> utils.getDefaultMimeType(poFormatId));

				var adt = new ArchiveDataType();
				adt.setType(po.getFormatId());
				adt.setArchiveDataID(s4FormatId);
				adt.setMimeType(s4MimeType.orElse(null));
				adt.setArchiveDataID(po.getID());

				adt.setValue(po.getBinaryData().getValue());
				archReq.getArchiveData().add(adt);

			}

			// process optional inputs
			if (req.getOptionalInputs() != null) {
				var oin = req.getOptionalInputs();
				var others = oin.getOther();
				var tresorOptIn = new AnyType();

				// convert to admissable options
				for (org.oasis_open.docs.dss_x.ns.base.AnyType next : others) {
					var newOptIn = utils.convertPreservePoOptIn(next, res);
					tresorOptIn.getAny().add(newOptIn);
				}

				// add only if there are inputoptions
				if (! tresorOptIn.getAny().isEmpty()) {
					archReq.setOptionalInputs(tresorOptIn);
				}
			}

			try {
				LOG.debug("Sending ArchiveSubmissionRequest to S4.");
				var archRes = client.archiveSubmission(archReq);
				LOG.debug("ArchiveSubmissionResponse received from S4.");

				utils.assertClientResultOk(archRes, res);

				// convert response back
				res.setPOID(archRes.getAOID());

				// process optional outputs
				if (archRes.getOptionalOutputs() != null) {
					var tresorOptOut = archRes.getOptionalOutputs();
					var optOut = new OptionalOutputsType();

					for (Object next : tresorOptOut.getAny()) {
						var converted = utils.convertPreservePoOutput(next, res);
						converted.ifPresent(v -> optOut.getOther().add(v));
					}

					// add only if there are outputoptions
					if (! optOut.getOther().isEmpty()) {
						res.setOptionalOutputs(optOut);
					}
				}

			} catch (SOAPFaultException ex) {
				LOG.error("Failed to invoked remote service.", ex);
				res.setResult(new ResultType()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
						.withResultMinor(PresCodes.INT_ERROR)
				);
			}

			return res;
		} catch (InputAssertionFailed ex) {
			LOG.warn("Assertion about input data failed: {}", ex.getMessage());
			LOG.debug("Assertion about input data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} catch (OutputAssertionFailed ex) {
			LOG.warn("Assertion about output data failed: {}", ex.getMessage());
			LOG.debug("Assertion about output data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} finally {
			LOG.debug("PreservePO finished.");
		}
	}


	@Override
	public UpdatePOCResponseType updatePOC(UpdatePOCType req) {
		LOG.debug("UpdatePOC called.");
		var res = new UpdatePOCResponseType();
		res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		try {
			var aoid = utils.assertPoid(req.getPOID(), res);

			// get dxaip
			POType po = utils.assertOneDeltaPOC(req.getDeltaPOC(), res);
			utils.assertAdmissibleDeltaFormat(po, res);
			var dxaip = utils.assertDXaipPresent(po, res);

			// check that poid matches dxaip
			utils.assertAoidMatches(dxaip, aoid, res);

			var archReq = new ArchiveUpdateRequest();
			archReq.setRequestID(req.getRequestID());
			archReq.setDXAIP(dxaip);

			// process optional inputs
			if (req.getOptionalInputs() != null) {
				var oin = req.getOptionalInputs();
				var others = oin.getOther();
				var tresorOptIn = new AnyType();

				// convert to admissable options
				for (org.oasis_open.docs.dss_x.ns.base.AnyType next : others) {
					var newOptIn = utils.convertUpdatePocOptIn(next, res);
					tresorOptIn.getAny().add(newOptIn);
				}

				// add only if there are inputoptions
				if (! tresorOptIn.getAny().isEmpty()) {
					archReq.setOptionalInputs(tresorOptIn);
				}
			}

			try {
				LOG.debug("Sending ArchiveUpdateRequest to S4.");
				var archRes = client.archiveUpdate(archReq);
				LOG.debug("ArchiveUpdateResponse received from S4.");

				utils.assertClientResultOk(archRes, res);

				// convert response back
				res.setVersionID(archRes.getVersionID());

				// process optional outputs
				if (archRes.getOptionalOutputs() != null) {
					var tresorOptOut = archRes.getOptionalOutputs();
					var optOut = new OptionalOutputsType();

					for (Object next : tresorOptOut.getAny()) {
						var converted = utils.convertPreservePoOutput(next, res);
						converted.ifPresent(v -> optOut.getOther().add(v));
					}

					// add only if there are outputoptions
					if (! optOut.getOther().isEmpty()) {
						res.setOptionalOutputs(optOut);
					}
				}

			} catch (SOAPFaultException ex) {
				LOG.error("Failed to invoked remote service.", ex);
				res.setResult(new ResultType()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
						.withResultMinor(PresCodes.INT_ERROR)
				);
			}

			return res;
		} catch (InputAssertionFailed ex) {
			LOG.warn("Assertion about input data failed: {}", ex.getMessage());
			LOG.debug("Assertion about input data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} catch (OutputAssertionFailed ex) {
			LOG.warn("Assertion about output data failed: {}", ex.getMessage());
			LOG.debug("Assertion about output data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} finally {
			LOG.debug("UpdatePOC finished.");
		}
	}

	@Override
	public ValidateEvidenceResponseType validateEvidence(ValidateEvidenceType req) {
		LOG.debug("ValidateEvidence called.");
		var res = new ValidateEvidenceResponseType();
		res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		try {
			var archReq = new VerifyRequest();
			archReq.setRequestID(req.getRequestID());

			// exactly one PO
			POType po = utils.assertOnePo(req.getPO(), res);
			utils.assertAdmissibleValidateFormat(po, res);

			// convert po
			var inputDocs = new InputDocuments();
			var inputDoc = new DocumentType();
			inputDocs.getDocumentOrTransformedDataOrDocumentHash().add(inputDoc);
			archReq.setInputDocuments(inputDocs);

			if (utils.isXaip(po)) {
				var xaip = utils.assertXaipPresent(po, res);
				var xaipOf = new de.bund.bsi.tr_esor.xaip.ObjectFactory();
				var inXml = new InlineXMLType();
				inXml.setAny(xaipOf.createXAIP(xaip));
				inputDoc.setInlineXML(inXml);
			} else {
				if (utils.isXmlXadesOrDigestList(po, res)) {
					// convert XML to binary
					utils.convertXmlToBinary(po, res);
				}

				var binary = utils.assertBinaryPresent(po, res);
				var inBin = new Base64Data();
				var poFormatId = po.getFormatId();
				var s4MimeType = Optional.ofNullable(po.getMimeType())
						.or(() -> utils.getDefaultMimeType(poFormatId));

				inBin.setValue(binary.getInputStream().readAllBytes());
				s4MimeType.ifPresent(inBin::setMimeType);
				inputDoc.setBase64Data(inBin);
			}

			// convert evidence
			if (req.getEvidence() != null) {
				var evidence = req.getEvidence();
				var formatID = utils.assertAdmissibleFormat(evidence, res);
				evidence.setFormatId(formatID);

				var sigObj = new SignatureObject();
				archReq.setSignatureObject(sigObj);

				if (utils.isErs(evidence)) {
					if (utils.isBinaryErs(evidence)) {
						var ersBin = utils.assertBinaryPresent(evidence, res);
						sigObj.setOther(utils.convertEvidenceRecord(ersBin, res, evidence.getPOID(), evidence.getVersionID()));
					} else {
						var ersXml = utils.assertXmlErsPresent(evidence, res);
						sigObj.setOther(utils.convertEvidenceRecord(ersXml.getValue(), res, evidence.getPOID(), evidence.getVersionID()));
					}
				} else {
					var ersBin = utils.assertBinaryPresent(evidence, res);
					sigObj.setBase64Signature(new Base64Signature()
							.withType(TypeConstants.CADES_ERS)
							.withValue(ersBin.getInputStream().readAllBytes())
					);
				}
			}

			// process optional inputs
			if (req.getOptionalInputs() != null) {
				var oin = req.getOptionalInputs();
				var others = oin.getOther();
				var tresorOptIn = new AnyType();

				// convert to admissable options
				for (org.oasis_open.docs.dss_x.ns.base.AnyType next : others) {
					var newOptIn = utils.convertValidateEvidence(next, res);
					tresorOptIn.getAny().add(newOptIn);
				}

				// add only if there are inputoptions
				if (! tresorOptIn.getAny().isEmpty()) {
					archReq.setOptionalInputs(tresorOptIn);
				}
			}

			try {
				LOG.debug("Sending VerifyRequest to S4.");
				var archRes = client.verify(archReq);
				LOG.debug("VerifyResponse received from S4.");

				utils.assertClientResultVerifyOk(archRes, res);

				// process optional outputs
				if (archRes.getOptionalOutputs() != null) {
					var tresorOptOut = archRes.getOptionalOutputs();

					for (Object next : tresorOptOut.getAny()) {
						var converted = utils.convertValidateEvidenceOutput(next, res);

						// at this point we know this is an evidence report
						if (utils.isVerificationReport(next)) {
							JAXBElement<VerificationReportType> report = (JAXBElement<VerificationReportType>) next;
							utils.getProofOfExistence(report.getValue()).ifPresent(res::setProofOfExistence);
						}

						converted.ifPresent(res::setValidationReport);
					}
				}

			} catch (SOAPFaultException ex) {
				LOG.error("Failed to invoked remote service.", ex);
				res.setResult(new ResultType()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
						.withResultMinor(PresCodes.INT_ERROR)
				);
			}

			return res;
		} catch (IOException ex) {
			LOG.error("Failed to copy input object.", ex);
			res.setResult(new ResultType()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
			);
			return res;
		} catch (InputAssertionFailed ex) {
			LOG.warn("Assertion about input data failed: {}", ex.getMessage());
			LOG.debug("Assertion about input data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} catch (OutputAssertionFailed ex) {
			LOG.warn("Assertion about output data failed: {}", ex.getMessage());
			LOG.debug("Assertion about output data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} finally {
			LOG.debug("ValidateEvidence finished.");
		}
	}

	@Override
	public ResponseType deletePO(DeletePOType req) {
		LOG.debug("DeletePO called.");
		var res = new ResponseType();
		res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		try {
			var aoid = utils.assertPoid(req.getPOID(), res);
			utils.assertDeletionMode(req.getMode(), res);
			var claimedRequestor = Optional.ofNullable(req.getClaimedRequestorName());
			var reason = Optional.ofNullable(req.getReason());

			utils.assertNoOptionalInputs(req.getOptionalInputs(), res);

			try {
				var archReq = new ArchiveDeletionRequest();
				archReq.setRequestID(req.getRequestID());
				archReq.setAOID(aoid);
				if (claimedRequestor.isPresent() || reason.isPresent()) {
					var optInReason = new ReasonOfDeletion();
					claimedRequestor.map(v -> new NameIDType()
							.withValue(v))
							.ifPresent(v -> optInReason.setRequestorName(v));
					reason.ifPresent(v -> optInReason.setRequestInfo(v));
					// add to request
					archReq.setOptionalInputs(new AnyType()
							.withAny(optInReason));
				}

				// call service
				LOG.debug("Sending ArchiveDeletionRequest to S4.");
				var archRes = client.archiveDeletion(archReq);
				LOG.debug("ArchiveDeletionResponse received from S4.");

				utils.assertClientResultDeletionOk(archRes, res);
				utils.assertNoOptionalOutputs(archRes.getOptionalOutputs(), res);

			} catch (SOAPFaultException ex) {
				LOG.error("Failed to invoked remote service.", ex);
				res.setResult(new ResultType()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
						.withResultMinor(PresCodes.INT_ERROR)
				);
			}

			return res;
		} catch (InputAssertionFailed ex) {
			LOG.warn("Assertion about input data failed: {}", ex.getMessage());
			LOG.debug("Assertion about input data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} catch (OutputAssertionFailed ex) {
			LOG.warn("Assertion about output data failed: {}", ex.getMessage());
			LOG.debug("Assertion about output data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} finally {
			LOG.debug("DeletePO finished.");
		}
	}

	@Override
	public RetrievePOResponseType retrievePO(RetrievePOType req) {
		LOG.debug("RetrievePO called.");
		var res = new RetrievePOResponseType();
		res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		try {
			var aoid = utils.assertPoid(req.getPOID(), res);
			var versionId = req.getVersionID();
			var subOfRetrieval = utils.assertSubjectOfRetrievalPoRetrieve(req.getSubjectOfRetrieval(), res);
			var poFormat = req.getPOFormat();
			var evidenceFormat = req.getEvidenceFormat();

			// process optional inputs
			if (req.getOptionalInputs() != null && ! req.getOptionalInputs().getOther().isEmpty()) {
				String msg = "Unsupported optional input given.";
				res.setResult(new ResultType()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
						.withResultMinor(PresCodes.NOT_SUPPORTED)
						.withResultMessage(utils.makeMsg(msg))
				);
				throw new InputAssertionFailed(msg);
			}

			try {
				// determine what to do next
				switch (subOfRetrieval) {
					case PO:
					case P_OWITH_EMBEDDED_EVIDENCE:
						processRetrievePoData(aoid, versionId, subOfRetrieval, poFormat, evidenceFormat, res);
						break;
					case EVIDENCE:
						processRetrievePoEvidence(aoid, versionId, evidenceFormat, res);
						break;
					default:
						throw new IllegalStateException("The system reached an invalid state.");
				}

			} catch (SOAPFaultException ex) {
				LOG.error("Failed to invoked remote service.", ex);
				res.setResult(new ResultType()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
						.withResultMinor(PresCodes.INT_ERROR)
				);
			}

			return res;
		} catch (InputAssertionFailed ex) {
			LOG.warn("Assertion about input data failed: {}", ex.getMessage());
			LOG.debug("Assertion about input data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} catch (OutputAssertionFailed ex) {
			LOG.warn("Assertion about output data failed: {}", ex.getMessage());
			LOG.debug("Assertion about output data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} finally {
			LOG.debug("RetrievePO finished.");
		}
	}

	private void processRetrievePoData(String aoid, List<String> versionId, SubjectOfRetrievalType retType, String poFormat, String evidenceFormat, RetrievePOResponseType res) throws InputAssertionFailed, OutputAssertionFailed {
		var archReq = new ArchiveRetrievalRequest();
		archReq.setRequestID(res.getRequestID());
		archReq.setAOID(aoid);
		archReq.getVersionID().addAll(versionId);

		var optIn = new AnyType();
		archReq.setOptionalInputs(optIn);

		// POFormat optional input
		poFormat = utils.assertAdmissibleFormat(poFormat, res);
		var poFormOpt = new org.etsi.uri._19512.v1_1.ObjectFactory().createPOFormat(poFormat);
		optIn.getAny().add(poFormOpt);

		// enbedded evidence optional input
		if (retType == SubjectOfRetrievalType.P_OWITH_EMBEDDED_EVIDENCE) {
			evidenceFormat = utils.assertRetrieveEvidenceFormat(evidenceFormat, res);
			var s4EvFormat = utils.convertToS4EvidenceFormat(evidenceFormat);
			var incErs = new ObjectFactory().createIncludeERS(s4EvFormat);
			optIn.getAny().add(incErs);
			archReq.setOptionalInputs(optIn);
		}

		utils.filterDefaults(archReq);

		// call service
		LOG.debug("Sending ArchiveRetrievalRequest to S4.");
		var archRes = client.archiveRetrieval(archReq);
		LOG.debug("ArchiveRetrievalResponse received from S4.");

		utils.assertClientResultOk(archRes, res);

		// convert response back
		if (archRes.getXAIP() != null) {
			var po = new POType()
					.withFormatId(poFormat)
					.withMimeType("application/xml")
					.withXmlData(new POType.XmlData()
					.withAny(new de.bund.bsi.tr_esor.xaip.ObjectFactory().createXAIP(archRes.getXAIP())));
			utils.assertReturnedXaipPresent(po, res);
			res.getPO().add(po);
		}

		// process optional outputs
		if (archRes.getOptionalOutputs() != null) {
			var tresorOptOut = archRes.getOptionalOutputs();
			var optOut = new OptionalOutputsType();

			for (Object next : tresorOptOut.getAny()) {
				var converted = utils.convertRetrievePoOutput(next, res);
				converted.ifPresent(v -> res.getPO().add(v));
			}
		}

		if (res.getPO().isEmpty()) {
			String msg = "No archive returned from S4.";
			res.setResult(new ResultType()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
					.withResultMinor(PresCodes.PARTLY_SUCCESSFUL)
					.withResultMessage(utils.makeMsg(msg))
			);
			throw new OutputAssertionFailed(msg);
		}
	}

	private void processRetrievePoEvidence(String aoid, List<String> versionId, String evidenceFormat, RetrievePOResponseType res) throws InputAssertionFailed, OutputAssertionFailed {
		var archReq = new ArchiveEvidenceRequest();
		archReq.setRequestID(res.getRequestID());
		archReq.setAOID(aoid);
		archReq.getVersionID().addAll(versionId);

		var optIn = new AnyType();
		archReq.setOptionalInputs(optIn);

		var defaultedEvidenceFormat = utils.assertRetrieveEvidenceFormat(evidenceFormat, res);
		var s4EvFormat = utils.convertToS4EvidenceFormat(defaultedEvidenceFormat);
		var ersFormat = new de.bund.bsi.tr_esor.api._1.ObjectFactory().createERSFormat(s4EvFormat);
		optIn.getAny().add(ersFormat);

		utils.filterDefaults(archReq);

		// call service
		LOG.debug("Sending ArchiveRetrievalRequest to S4.");
		var archRes = client.archiveEvidence(archReq);
		LOG.debug("ArchiveRetrievalResponse received from S4.");

		utils.assertClientResultOk(archRes, res);

		// no optionaloutputs allowed
		utils.assertNoOptionalOutputs(archRes.getOptionalOutputs(), res);

		// convert response back
		archRes.getEvidenceRecord().stream()
				.map(e -> new POType()
					.withFormatId(defaultedEvidenceFormat)
					.withXmlData(new POType.XmlData()
					.withAny(new de.bund.bsi.tr_esor.xaip.ObjectFactory().createEvidenceRecord(e))))
				.forEachOrdered(res.getPO()::add);

		if (res.getPO().isEmpty()) {
			String msg = "No evidence returned from S4.";
			res.setResult(new ResultType()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.PARTLY_SUCCESSFUL)
					.withResultMessage(utils.makeMsg(msg))
			);
			throw new OutputAssertionFailed(msg);
		}
	}

	@Override
	public RetrieveTraceResponseType retrieveTrace(RetrieveTraceType req) {
		LOG.debug("RetrieveTrace called.");
		var res = new RetrieveTraceResponseType();
		res.setResult(new ResultType()
			.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		if (!profileSupplier.isTraceSupported()) {
			res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
				.withResultMinor(PresCodes.NOT_SUPPORTED)
			);
			res.setRequestID(req.getRequestID());
			return res;
		}

		try {
			utils.assertNoOptionalInputs(req.getOptionalInputs(), res);

			try {
				var atr = new ArchiveTraceRequest();
				atr.setAOID(req.getPOID());
				atr.setRequestID(req.getRequestID());
				var s4resp = client.archiveTrace(atr);

				utils.assertClientResultOk(s4resp, res);

				res.setTrace(s4resp.getTrace());

			} catch (SOAPFaultException ex) {
				LOG.error("Failed to invoked remote service.", ex);
				res.setResult(new ResultType()
					.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
					.withResultMinor(PresCodes.INT_ERROR)
				);
			}
		} catch (InputAssertionFailed ex) {
			LOG.warn("Assertion about input data failed: {}", ex.getMessage());
			LOG.debug("Assertion about input data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} catch (OutputAssertionFailed ex) {
			LOG.warn("Assertion about output data failed: {}", ex.getMessage());
			LOG.debug("Assertion about output data failed.", ex);
			// res has been updated by the assert statement
			//assure empty trace in if error happens due to schema compliance.
			res.setTrace(new TraceType());
			return res;
		}

		return res;

	}

	@Override
	public SearchResponseType search(SearchType req) {
		LOG.debug("Search called.");
		var res = new SearchResponseType();
		res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_SUCCESS)
		);
		res.setRequestID(req.getRequestID());

		if (!profileSupplier.isSearchSupported()) {
			res.setResult(new ResultType()
				.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_REQUESTER_ERROR)
				.withResultMinor(PresCodes.NOT_SUPPORTED)
			);
			res.setRequestID(req.getRequestID());
			return res;
		}

		try {

			utils.assertNoOptionalInputs(req.getOptionalInputs(), res);

			var filterObj = utils.assertAndConvertFilter(req, res);

			var archReq = new ArchiveDataRequest();
			archReq.setRequestID(req.getRequestID());
			archReq.setAOID(filterObj.getAOID());

			var dl = new DataLocation();
			var xPathQuery = new de.bund.bsi.tr_esor.api._1.ObjectFactory().createXPathFilter(filterObj.getXPath());
			dl.setType("http://www.w3.org/TR/2007/REC-xpath20-20070123/");
			dl.getAny().add(xPathQuery);
			archReq.getDataLocation().add(dl);

			try {
				LOG.debug("Sending ArchiveDataRequest to S4.");
				var archRes = client.archiveData(archReq);
				LOG.debug("ArchiveSubmissionResponse received from S4.");

				utils.assertNoOptionalOutputs(archRes.getOptionalOutputs(), res);
				utils.assertClientResultOk(archRes, res);
				utils.assertXaipDataPresent(archRes, res);

				var optOut = new OptionalOutputsType();
				for (var x : archRes.getXAIPData()) {
					var xaipDataAny = utils.convertXAIPData(x, res);
					optOut.getOther().add(xaipDataAny);
				}
				if (! optOut.getOther().isEmpty()) {
					res.setOptionalOutputs(optOut);
				}

			} catch (SOAPFaultException ex) {
				LOG.error("Failed to invoked remote service.", ex);
				res.setResult(new ResultType()
						.withResultMajor(ResultType.ResultMajor.URN_OASIS_NAMES_TC_DSS_1_0_RESULTMAJOR_RESPONDER_ERROR)
						.withResultMinor(PresCodes.INT_ERROR)
				);
			}

			return res;
		} catch (InputAssertionFailed ex) {
			LOG.warn("Assertion about input data failed: {}", ex.getMessage());
			LOG.debug("Assertion about input data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} catch (OutputAssertionFailed ex) {
			LOG.warn("Assertion about output data failed: {}", ex.getMessage());
			LOG.debug("Assertion about output data failed.", ex);
			// res has been updated by the assert statement
			return res;
		} finally {
			LOG.debug("Search finished.");
		}
	}

}
