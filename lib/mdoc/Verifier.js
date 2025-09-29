"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Verifier = void 0;
const compare_versions_1 = require("compare-versions");
const x509_1 = require("@peculiar/x509");
const jose_1 = require("jose");
const buffer_1 = require("buffer");
const cose_kit_1 = require("cose-kit");
const uncrypto_1 = __importDefault(require("uncrypto"));
const utils_1 = require("./utils");
const checkCallback_1 = require("./checkCallback");
const parser_1 = require("./parser");
const DeviceSignedDocument_1 = require("./model/DeviceSignedDocument");
const MDL_NAMESPACE = 'org.iso.18013.5.1';
const DIGEST_ALGS = {
    'SHA-256': 'sha256',
    'SHA-384': 'sha384',
    'SHA-512': 'sha512',
};
class Verifier {
    /**
     *
     * @param issuersRootCertificates The IACA root certificates list of the supported issuers.
     */
    constructor(issuersRootCertificates) {
        this.issuersRootCertificates = issuersRootCertificates;
    }
    async verifyIssuerSignature(issuerAuth, disableCertificateChainValidation, onCheckG) {
        const onCheck = (0, checkCallback_1.onCatCheck)(onCheckG, 'ISSUER_AUTH');
        const { certificate, countryName } = issuerAuth;
        const verificationKey = certificate ? (await (0, jose_1.importX509)(certificate.toString(), issuerAuth.algName)) : undefined;
        if (!disableCertificateChainValidation) {
            try {
                await issuerAuth.verifyX509Chain(this.issuersRootCertificates);
                onCheck({
                    status: 'PASSED',
                    check: 'Issuer certificate must be valid',
                    id: checkCallback_1.VerificationAssessmentId.ISSUER_AUTH.IssuerCertificateValidity,
                });
            }
            catch (err) {
                onCheck({
                    status: 'FAILED',
                    check: 'Issuer certificate must be valid',
                    id: checkCallback_1.VerificationAssessmentId.ISSUER_AUTH.IssuerCertificateValidity,
                    reason: err.message,
                });
            }
        }
        const verificationResult = verificationKey && await issuerAuth.verify(verificationKey);
        onCheck({
            status: verificationResult ? 'PASSED' : 'FAILED',
            check: 'Issuer signature must be valid',
            id: checkCallback_1.VerificationAssessmentId.ISSUER_AUTH.IssuerSignatureValidity,
        });
        // Validity
        const { validityInfo } = issuerAuth.decodedPayload;
        const now = new Date();
        onCheck({
            status: certificate && validityInfo && (validityInfo.signed < certificate.notBefore || validityInfo.signed > certificate.notAfter) ? 'FAILED' : 'PASSED',
            check: 'The MSO signed date must be within the validity period of the certificate',
            id: checkCallback_1.VerificationAssessmentId.ISSUER_AUTH.MsoSignedDateWithinCertificateValidity,
            reason: certificate && validityInfo
                ? `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${certificate.notBefore.toUTCString()} to ${certificate.notAfter.toUTCString()})`
                : 'Certificate or validity information not available',
        });
        onCheck({
            status: validityInfo && (now < validityInfo.validFrom || now > validityInfo.validUntil) ? 'FAILED' : 'PASSED',
            check: 'The MSO must be valid at the time of verification',
            id: checkCallback_1.VerificationAssessmentId.ISSUER_AUTH.MsoValidityAtVerificationTime,
            reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
        });
        onCheck({
            status: countryName ? 'PASSED' : 'FAILED',
            check: 'Country name (C) must be present in the issuer certificate\'s subject distinguished name',
            id: checkCallback_1.VerificationAssessmentId.ISSUER_AUTH.IssuerSubjectCountryNamePresence,
        });
    }
    async verifyDeviceSignature(document, options) {
        const onCheck = (0, checkCallback_1.onCatCheck)(options.onCheck, 'DEVICE_AUTH');
        if (!(document instanceof DeviceSignedDocument_1.DeviceSignedDocument)) {
            onCheck({
                status: 'FAILED',
                check: 'The document is not signed by the device.',
                id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DocumentDeviceSignaturePresence,
            });
            return;
        }
        const { deviceAuth, nameSpaces } = document.deviceSigned;
        const { docType } = document;
        const { deviceKeyInfo } = document.issuerSigned.issuerAuth.decodedPayload;
        const { deviceKey: deviceKeyCoseKey } = deviceKeyInfo || {};
        // Prevent cloning of the mdoc and mitigate man in the middle attacks
        if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
            onCheck({
                status: 'FAILED',
                check: 'Device Auth must contain a deviceSignature or deviceMac element',
                id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceAuthSignatureOrMacPresence,
            });
            return;
        }
        if (!options.sessionTranscriptBytes) {
            onCheck({
                status: 'FAILED',
                check: 'Session Transcript Bytes missing from options, aborting device signature check',
                id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.SessionTranscriptProvided,
            });
            return;
        }
        const deviceAuthenticationBytes = (0, utils_1.calculateDeviceAutenticationBytes)(options.sessionTranscriptBytes, docType, nameSpaces);
        if (!deviceKeyCoseKey) {
            onCheck({
                status: 'FAILED',
                check: 'Issuer signature must contain the device key.',
                id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceKeyAvailableInIssuerAuth,
                reason: 'Unable to verify deviceAuth signature: missing device key in issuerAuth',
            });
            return;
        }
        if (deviceAuth.deviceSignature) {
            const deviceKey = await (0, cose_kit_1.importCOSEKey)(deviceKeyCoseKey);
            // ECDSA/EdDSA authentication
            try {
                const ds = deviceAuth.deviceSignature;
                const verificationResult = await new cose_kit_1.Sign1(ds.protectedHeaders, ds.unprotectedHeaders, deviceAuthenticationBytes, ds.signature).verify(deviceKey);
                onCheck({
                    status: verificationResult ? 'PASSED' : 'FAILED',
                    check: 'Device signature must be valid',
                    id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceSignatureValidity,
                });
            }
            catch (err) {
                onCheck({
                    status: 'FAILED',
                    check: 'Device signature must be valid',
                    id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceSignatureValidity,
                    reason: `Unable to verify deviceAuth signature (ECDSA/EdDSA): ${err.message}`,
                });
            }
            return;
        }
        // MAC authentication
        onCheck({
            status: deviceAuth.deviceMac ? 'PASSED' : 'FAILED',
            check: 'Device MAC must be present when using MAC authentication',
            id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceMacPresence,
        });
        if (!deviceAuth.deviceMac) {
            return;
        }
        onCheck({
            status: deviceAuth.deviceMac.hasSupportedAlg() ? 'PASSED' : 'FAILED',
            check: 'Device MAC must use alg 5 (HMAC 256/256)',
            id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceMacAlgorithmCorrectness,
        });
        if (!deviceAuth.deviceMac.hasSupportedAlg()) {
            return;
        }
        onCheck({
            status: options.ephemeralPrivateKey ? 'PASSED' : 'FAILED',
            check: 'Ephemeral private key must be present when using MAC authentication',
            id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.EphemeralKeyPresence,
        });
        if (!options.ephemeralPrivateKey) {
            return;
        }
        try {
            const ephemeralMacKey = await (0, utils_1.calculateEphemeralMacKey)(options.ephemeralPrivateKey, deviceKeyCoseKey, options.sessionTranscriptBytes);
            const isValid = await deviceAuth.deviceMac.verify(ephemeralMacKey, undefined, deviceAuthenticationBytes);
            onCheck({
                status: isValid ? 'PASSED' : 'FAILED',
                check: 'Device MAC must be valid',
                id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceMacValidity,
            });
        }
        catch (err) {
            onCheck({
                status: 'FAILED',
                check: 'Device MAC must be valid',
                id: checkCallback_1.VerificationAssessmentId.DEVICE_AUTH.DeviceMacValidity,
                reason: `Unable to verify deviceAuth MAC: ${err.message}`,
            });
        }
    }
    async verifyData(mdoc, onCheckG) {
        // Confirm that the mdoc data has not changed since issuance
        const { issuerAuth } = mdoc.issuerSigned;
        const { valueDigests, digestAlgorithm } = issuerAuth.decodedPayload;
        const onCheck = (0, checkCallback_1.onCatCheck)(onCheckG, 'DATA_INTEGRITY');
        onCheck({
            status: digestAlgorithm && DIGEST_ALGS[digestAlgorithm] ? 'PASSED' : 'FAILED',
            check: 'Issuer Auth must include a supported digestAlgorithm element',
            id: checkCallback_1.VerificationAssessmentId.DATA_INTEGRITY.IssuerAuthDigestAlgorithmSupported,
        });
        const nameSpaces = mdoc.issuerSigned.nameSpaces || {};
        await Promise.all(Object.keys(nameSpaces).map(async (ns) => {
            onCheck({
                status: valueDigests.has(ns) ? 'PASSED' : 'FAILED',
                check: `Issuer Auth must include digests for namespace: ${ns}`,
                id: checkCallback_1.VerificationAssessmentId.DATA_INTEGRITY.IssuerAuthNamespaceDigestPresence,
            });
            const verifications = await Promise.all(nameSpaces[ns].map(async (ev) => {
                const isValid = await ev.isValid(ns, issuerAuth);
                return { ev, ns, isValid };
            }));
            verifications.filter((v) => v.isValid).forEach((v) => {
                onCheck({
                    status: 'PASSED',
                    check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
                    id: checkCallback_1.VerificationAssessmentId.DATA_INTEGRITY.AttributeDigestMatch,
                });
            });
            verifications.filter((v) => !v.isValid).forEach((v) => {
                onCheck({
                    status: 'FAILED',
                    check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
                    id: checkCallback_1.VerificationAssessmentId.DATA_INTEGRITY.AttributeDigestMatch,
                });
            });
            if (ns === MDL_NAMESPACE) {
                const issuer = issuerAuth.certificate?.issuerName;
                if (!issuer) {
                    onCheck({
                        status: 'FAILED',
                        check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
                        id: checkCallback_1.VerificationAssessmentId.DATA_INTEGRITY.IssuingCountryMatchesCertificate,
                        reason: "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
                    });
                }
                else {
                    const invalidCountry = verifications.filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
                        .find((v) => !v.isValid || !v.ev.matchCertificate(ns, issuerAuth));
                    onCheck({
                        status: invalidCountry ? 'FAILED' : 'PASSED',
                        check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
                        id: checkCallback_1.VerificationAssessmentId.DATA_INTEGRITY.IssuingCountryMatchesCertificate,
                        reason: invalidCountry ?
                            `The 'issuing_country' (${invalidCountry.ev.elementValue}) must match the 'countryName' (${issuerAuth.countryName}) in the subject field within the issuer certificate` :
                            undefined,
                    });
                    const invalidJurisdiction = verifications.filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
                        .find((v) => !v.isValid || (issuerAuth.stateOrProvince && !v.ev.matchCertificate(ns, issuerAuth)));
                    onCheck({
                        status: invalidJurisdiction ? 'FAILED' : 'PASSED',
                        check: "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
                        id: checkCallback_1.VerificationAssessmentId.DATA_INTEGRITY.IssuingJurisdictionMatchesCertificate,
                        reason: invalidJurisdiction ?
                            `The 'issuing_jurisdiction' (${invalidJurisdiction.ev.elementValue}) must match the 'stateOrProvinceName' (${issuerAuth.stateOrProvince}) in the subject field within the issuer certificate` :
                            undefined,
                    });
                }
            }
        }));
    }
    /**
     * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
     *
     * @param encodedDeviceResponse
     * @param options.encodedSessionTranscript The CBOR encoded SessionTranscript.
     * @param options.ephemeralReaderKey The private part of the ephemeral key used in the session where the DeviceResponse was obtained. This is only required if the DeviceResponse is using the MAC method for device authentication.
     */
    async verify(encodedDeviceResponse, options = {}) {
        const onCheck = (0, checkCallback_1.buildCallback)(options.onCheck);
        const dr = (0, parser_1.parse)(encodedDeviceResponse);
        onCheck({
            status: dr.version ? 'PASSED' : 'FAILED',
            check: 'Device Response must include "version" element.',
            id: checkCallback_1.VerificationAssessmentId.DOCUMENT_FORMAT.DeviceResponseVersionPresence,
            category: 'DOCUMENT_FORMAT',
        });
        onCheck({
            status: (0, compare_versions_1.compareVersions)(dr.version, '1.0') >= 0 ? 'PASSED' : 'FAILED',
            check: 'Device Response version must be 1.0 or greater',
            id: checkCallback_1.VerificationAssessmentId.DOCUMENT_FORMAT.DeviceResponseVersionSupported,
            category: 'DOCUMENT_FORMAT',
        });
        onCheck({
            status: dr.documents && dr.documents.length > 0 ? 'PASSED' : 'FAILED',
            check: 'Device Response must include at least one document.',
            id: checkCallback_1.VerificationAssessmentId.DOCUMENT_FORMAT.DeviceResponseDocumentPresence,
            category: 'DOCUMENT_FORMAT',
        });
        for (const document of dr.documents) {
            const { issuerAuth } = document.issuerSigned;
            await this.verifyIssuerSignature(issuerAuth, options.disableCertificateChainValidation, onCheck);
            await this.verifyDeviceSignature(document, {
                ephemeralPrivateKey: options.ephemeralReaderKey,
                sessionTranscriptBytes: options.encodedSessionTranscript,
                onCheck,
            });
            await this.verifyData(document, onCheck);
        }
        return dr;
    }
    async getDiagnosticInformation(encodedDeviceResponse, options) {
        const dr = [];
        const decoded = await this.verify(
        // @ts-ignore
        encodedDeviceResponse, {
            ...options,
            onCheck: (check) => dr.push(check),
        });
        const document = decoded.documents[0];
        const { issuerAuth } = document.issuerSigned;
        const issuerCert = issuerAuth.x5chain &&
            issuerAuth.x5chain.length > 0 &&
            new x509_1.X509Certificate(issuerAuth.x5chain[0]);
        const attributes = (await Promise.all(Object.keys(document.issuerSigned.nameSpaces).map(async (ns) => {
            const items = document.issuerSigned.nameSpaces[ns];
            return Promise.all(items.map(async (item) => {
                const isValid = await item.isValid(ns, issuerAuth);
                return {
                    ns,
                    id: item.elementIdentifier,
                    value: item.elementValue,
                    isValid,
                    matchCertificate: item.matchCertificate(ns, issuerAuth),
                };
            }));
        }))).flat();
        const deviceAttributes = document instanceof DeviceSignedDocument_1.DeviceSignedDocument ?
            Object.entries(document.deviceSigned.nameSpaces).map(([ns, items]) => {
                return Object.entries(items).map(([id, value]) => {
                    return {
                        ns,
                        id,
                        value,
                    };
                });
            }).flat() : undefined;
        let deviceKey;
        if (document?.issuerSigned.issuerAuth) {
            const { deviceKeyInfo } = document.issuerSigned.issuerAuth.decodedPayload;
            if (deviceKeyInfo?.deviceKey) {
                deviceKey = (0, cose_kit_1.COSEKeyToJWK)(deviceKeyInfo.deviceKey);
            }
        }
        const disclosedAttributes = attributes.filter((attr) => attr.isValid).length;
        const totalAttributes = Array.from(document
            .issuerSigned
            .issuerAuth
            .decodedPayload
            .valueDigests
            .entries()).reduce((prev, [, digests]) => prev + digests.size, 0);
        return {
            general: {
                version: decoded.version,
                type: 'DeviceResponse',
                status: decoded.status,
                documents: decoded.documents.length,
            },
            validityInfo: document.issuerSigned.issuerAuth.decodedPayload.validityInfo,
            issuerCertificate: issuerCert ? {
                subjectName: issuerCert.subjectName.toString(),
                pem: issuerCert.toString(),
                notBefore: issuerCert.notBefore,
                notAfter: issuerCert.notAfter,
                serialNumber: issuerCert.serialNumber,
                thumbprint: buffer_1.Buffer.from(await issuerCert.getThumbprint(uncrypto_1.default)).toString('hex'),
            } : undefined,
            issuerSignature: {
                alg: document.issuerSigned.issuerAuth.algName,
                isValid: dr
                    .filter((check) => check.category === 'ISSUER_AUTH')
                    .every((check) => check.status === 'PASSED'),
                reasons: dr
                    .filter((check) => check.category === 'ISSUER_AUTH' && check.status === 'FAILED')
                    .map((check) => check.reason ?? check.check),
                digests: Object.fromEntries(Array.from(document
                    .issuerSigned
                    .issuerAuth
                    .decodedPayload
                    .valueDigests
                    .entries()).map(([ns, digests]) => [ns, digests.size])),
            },
            deviceKey: {
                jwk: deviceKey,
            },
            deviceSignature: document instanceof DeviceSignedDocument_1.DeviceSignedDocument ? {
                alg: document.deviceSigned.deviceAuth.deviceSignature?.algName ??
                    document.deviceSigned.deviceAuth.deviceMac?.algName,
                isValid: dr
                    .filter((check) => check.category === 'DEVICE_AUTH')
                    .every((check) => check.status === 'PASSED'),
                reasons: dr
                    .filter((check) => check.category === 'DEVICE_AUTH' && check.status === 'FAILED')
                    .map((check) => check.reason ?? check.check),
            } : undefined,
            dataIntegrity: {
                disclosedAttributes: `${disclosedAttributes} of ${totalAttributes}`,
                isValid: dr
                    .filter((check) => check.category === 'DATA_INTEGRITY')
                    .every((check) => check.status === 'PASSED'),
                reasons: dr
                    .filter((check) => check.category === 'DATA_INTEGRITY' && check.status === 'FAILED')
                    .map((check) => check.reason ?? check.check),
            },
            attributes,
            deviceAttributes,
        };
    }
}
exports.Verifier = Verifier;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVmVyaWZpZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWRvYy9WZXJpZmllci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSx1REFBbUQ7QUFDbkQseUNBQWlEO0FBQ2pELCtCQUFnRDtBQUNoRCxtQ0FBZ0M7QUFDaEMsdUNBQThEO0FBQzlELHdEQUE4QjtBQUc5QixtQ0FHaUI7QUFLakIsbURBQStJO0FBRS9JLHFDQUFpQztBQUdqQyx1RUFBb0U7QUFFcEUsTUFBTSxhQUFhLEdBQUcsbUJBQW1CLENBQUM7QUFFMUMsTUFBTSxXQUFXLEdBQUc7SUFDbEIsU0FBUyxFQUFFLFFBQVE7SUFDbkIsU0FBUyxFQUFFLFFBQVE7SUFDbkIsU0FBUyxFQUFFLFFBQVE7Q0FDUyxDQUFDO0FBRS9CLE1BQWEsUUFBUTtJQUNuQjs7O09BR0c7SUFDSCxZQUE0Qix1QkFBaUM7UUFBakMsNEJBQXVCLEdBQXZCLHVCQUF1QixDQUFVO0lBQUksQ0FBQztJQUUxRCxLQUFLLENBQUMscUJBQXFCLENBQ2pDLFVBQXNCLEVBQ3RCLGlDQUEwQyxFQUMxQyxRQUF5QztRQUV6QyxNQUFNLE9BQU8sR0FBRyxJQUFBLDBCQUFVLEVBQUMsUUFBUSxFQUFFLGFBQWEsQ0FBQyxDQUFDO1FBQ3BELE1BQU0sRUFBRSxXQUFXLEVBQUUsV0FBVyxFQUFFLEdBQUcsVUFBVSxDQUFDO1FBQ2hELE1BQU0sZUFBZSxHQUF3QixXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxJQUFBLGlCQUFVLEVBQzFFLFdBQVcsQ0FBQyxRQUFRLEVBQUUsRUFDdEIsVUFBVSxDQUFDLE9BQU8sQ0FDbkIsQ0FBQyxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUM7UUFFZixJQUFJLENBQUMsaUNBQWlDLEVBQUU7WUFDdEMsSUFBSTtnQkFDRixNQUFNLFVBQVUsQ0FBQyxlQUFlLENBQUMsSUFBSSxDQUFDLHVCQUF1QixDQUFDLENBQUM7Z0JBQy9ELE9BQU8sQ0FBQztvQkFD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