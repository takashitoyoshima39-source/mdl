"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.onCatCheck = exports.buildCallback = exports.defaultCallback = exports.VerificationAssessmentId = void 0;
const debug_1 = __importDefault(require("debug"));
const errors_1 = require("./errors");
const log = (0, debug_1.default)('mdl');
exports.VerificationAssessmentId = {
    ISSUER_AUTH: {
        IssuerCertificateValidity: 'ISSUER_CERTIFICATE_VALIDITY',
        IssuerSignatureValidity: 'ISSUER_SIGNATURE_VALIDITY',
        MsoSignedDateWithinCertificateValidity: 'MSO_SIGNED_DATE_WITHIN_CERTIFICATE_VALIDITY',
        MsoValidityAtVerificationTime: 'MSO_VALIDITY_AT_VERIFICATION_TIME',
        IssuerSubjectCountryNamePresence: 'ISSUER_SUBJECT_COUNTRY_NAME_PRESENCE',
    },
    DEVICE_AUTH: {
        DocumentDeviceSignaturePresence: 'DOCUMENT_DEVICE_SIGNATURE_PRESENCE',
        DeviceAuthSignatureOrMacPresence: 'DEVICE_AUTH_SIGNATURE_OR_MAC_PRESENCE',
        SessionTranscriptProvided: 'SESSION_TRANSCRIPT_PROVIDED',
        DeviceKeyAvailableInIssuerAuth: 'DEVICE_KEY_AVAILABLE_IN_ISSUERAUTH',
        DeviceSignatureValidity: 'DEVICE_SIGNATURE_VALIDITY',
        DeviceMacPresence: 'DEVICE_MAC_PRESENCE',
        DeviceMacAlgorithmCorrectness: 'DEVICE_MAC_ALGORITHM_CORRECTNESS',
        EphemeralKeyPresence: 'EPHEMERAL_KEY_PRESENCE',
        DeviceMacValidity: 'DEVICE_MAC_VALIDITY',
    },
    DATA_INTEGRITY: {
        IssuerAuthDigestAlgorithmSupported: 'ISSUER_AUTH_DIGEST_ALGORITHM_SUPPORTED',
        IssuerAuthNamespaceDigestPresence: 'ISSUER_AUTH_NAMESPACE_DIGEST_PRESENCE',
        AttributeDigestMatch: 'ATTRIBUTE_DIGEST_MATCH',
        IssuingCountryMatchesCertificate: 'ISSUING_COUNTRY_MATCHES_CERTIFICATE',
        IssuingJurisdictionMatchesCertificate: 'ISSUING_JURISDICTION_MATCHES_CERTIFICATE',
    },
    DOCUMENT_FORMAT: {
        DeviceResponseVersionPresence: 'DEVICE_RESPONSE_VERSION_PRESENCE',
        DeviceResponseVersionSupported: 'DEVICE_RESPONSE_VERSION_SUPPORTED',
        DeviceResponseDocumentPresence: 'DEVICE_RESPONSE_DOCUMENT_PRESENCE',
    },
};
exports.defaultCallback = ((verification) => {
    log(`Verification: ${verification.check} => ${verification.status}`);
    if (verification.status !== 'FAILED')
        return;
    throw new errors_1.MDLError(verification.reason ?? verification.check, verification.id);
});
const buildCallback = (callback) => {
    if (typeof callback === 'undefined') {
        return exports.defaultCallback;
    }
    return (item) => {
        callback(item, exports.defaultCallback);
    };
};
exports.buildCallback = buildCallback;
const onCatCheck = (onCheck, category) => {
    return (item) => {
        onCheck({ ...item, category }, exports.defaultCallback);
    };
};
exports.onCatCheck = onCatCheck;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2hlY2tDYWxsYmFjay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9tZG9jL2NoZWNrQ2FsbGJhY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsa0RBQTBCO0FBQzFCLHFDQUFvQztBQUVwQyxNQUFNLEdBQUcsR0FBRyxJQUFBLGVBQUssRUFBQyxLQUFLLENBQUMsQ0FBQztBQUVaLFFBQUEsd0JBQXdCLEdBQUc7SUFDdEMsV0FBVyxFQUFFO1FBQ1gseUJBQXlCLEVBQUUsNkJBQTZCO1FBQ3hELHVCQUF1QixFQUFFLDJCQUEyQjtRQUNwRCxzQ0FBc0MsRUFBRSw2Q0FBNkM7UUFDckYsNkJBQTZCLEVBQUUsbUNBQW1DO1FBQ2xFLGdDQUFnQyxFQUFFLHNDQUFzQztLQUN6RTtJQUVELFdBQVcsRUFBRTtRQUNYLCtCQUErQixFQUFFLG9DQUFvQztRQUNyRSxnQ0FBZ0MsRUFBRSx1Q0FBdUM7UUFDekUseUJBQXlCLEVBQUUsNkJBQTZCO1FBQ3hELDhCQUE4QixFQUFFLG9DQUFvQztRQUNwRSx1QkFBdUIsRUFBRSwyQkFBMkI7UUFDcEQsaUJBQWlCLEVBQUUscUJBQXFCO1FBQ3hDLDZCQUE2QixFQUFFLGtDQUFrQztRQUNqRSxvQkFBb0IsRUFBRSx3QkFBd0I7UUFDOUMsaUJBQWlCLEVBQUUscUJBQXFCO0tBQ3pDO0lBRUQsY0FBYyxFQUFFO1FBQ2Qsa0NBQWtDLEVBQUUsd0NBQXdDO1FBQzVFLGlDQUFpQyxFQUFFLHVDQUF1QztRQUMxRSxvQkFBb0IsRUFBRSx3QkFBd0I7UUFDOUMsZ0NBQWdDLEVBQUUscUNBQXFDO1FBQ3ZFLHFDQUFxQyxFQUFFLDBDQUEwQztLQUNsRjtJQUVELGVBQWUsRUFBRTtRQUNmLDZCQUE2QixFQUFFLGtDQUFrQztRQUNqRSw4QkFBOEIsRUFBRSxtQ0FBbUM7UUFDbkUsOEJBQThCLEVBQUUsbUNBQW1DO0tBQ3BFO0NBQ08sQ0FBQztBQWdCRSxRQUFBLGVBQWUsR0FBeUIsQ0FBQyxDQUFDLFlBQVksRUFBRSxFQUFFO0lBQ3JFLEdBQUcsQ0FBQyxpQkFBaUIsWUFBWSxDQUFDLEtBQUssT0FBTyxZQUFZLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQztJQUNyRSxJQUFJLFlBQVksQ0FBQyxNQUFNLEtBQUssUUFBUTtRQUFFLE9BQU87SUFDN0MsTUFBTSxJQUFJLGlCQUFRLENBQUMsWUFBWSxDQUFDLE1BQU0sSUFBSSxZQUFZLENBQUMsS0FBSyxFQUFFLFlBQVksQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUNqRixDQUFDLENBQUMsQ0FBQztBQUVJLE1BQU0sYUFBYSxHQUFHLENBQUMsUUFBMEMsRUFBd0IsRUFBRTtJQUNoRyxJQUFJLE9BQU8sUUFBUSxLQUFLLFdBQVcsRUFBRTtRQUFFLE9BQU8sdUJBQWUsQ0FBQztLQUFFO0lBQ2hFLE9BQU8sQ0FBQyxJQUE0QixFQUFFLEVBQUU7UUFDdEMsUUFBUSxDQUFDLElBQUksRUFBRSx1QkFBZSxDQUFDLENBQUM7SUFDbEMsQ0FBQyxDQUFDO0FBQ0osQ0FBQyxDQUFDO0FBTFcsUUFBQSxhQUFhLGlCQUt4QjtBQUVLLE1BQU0sVUFBVSxHQUFHLENBQWtELE9BQXdDLEVBQUUsUUFBVyxFQUFFLEVBQUU7SUFDbkksT0FBTyxDQUFDLElBQXdFLEVBQUUsRUFBRTtRQUNsRixPQUFPLENBQUMsRUFBRSxHQUFHLElBQUksRUFBRSxRQUFRLEVBQTRCLEVBQUUsdUJBQWUsQ0FBQyxDQUFDO0lBQzVFLENBQUMsQ0FBQztBQUNKLENBQUMsQ0FBQztBQUpXLFFBQUEsVUFBVSxjQUlyQiJ9