export declare const VerificationAssessmentId: {
    readonly ISSUER_AUTH: {
        readonly IssuerCertificateValidity: "ISSUER_CERTIFICATE_VALIDITY";
        readonly IssuerSignatureValidity: "ISSUER_SIGNATURE_VALIDITY";
        readonly MsoSignedDateWithinCertificateValidity: "MSO_SIGNED_DATE_WITHIN_CERTIFICATE_VALIDITY";
        readonly MsoValidityAtVerificationTime: "MSO_VALIDITY_AT_VERIFICATION_TIME";
        readonly IssuerSubjectCountryNamePresence: "ISSUER_SUBJECT_COUNTRY_NAME_PRESENCE";
    };
    readonly DEVICE_AUTH: {
        readonly DocumentDeviceSignaturePresence: "DOCUMENT_DEVICE_SIGNATURE_PRESENCE";
        readonly DeviceAuthSignatureOrMacPresence: "DEVICE_AUTH_SIGNATURE_OR_MAC_PRESENCE";
        readonly SessionTranscriptProvided: "SESSION_TRANSCRIPT_PROVIDED";
        readonly DeviceKeyAvailableInIssuerAuth: "DEVICE_KEY_AVAILABLE_IN_ISSUERAUTH";
        readonly DeviceSignatureValidity: "DEVICE_SIGNATURE_VALIDITY";
        readonly DeviceMacPresence: "DEVICE_MAC_PRESENCE";
        readonly DeviceMacAlgorithmCorrectness: "DEVICE_MAC_ALGORITHM_CORRECTNESS";
        readonly EphemeralKeyPresence: "EPHEMERAL_KEY_PRESENCE";
        readonly DeviceMacValidity: "DEVICE_MAC_VALIDITY";
    };
    readonly DATA_INTEGRITY: {
        readonly IssuerAuthDigestAlgorithmSupported: "ISSUER_AUTH_DIGEST_ALGORITHM_SUPPORTED";
        readonly IssuerAuthNamespaceDigestPresence: "ISSUER_AUTH_NAMESPACE_DIGEST_PRESENCE";
        readonly AttributeDigestMatch: "ATTRIBUTE_DIGEST_MATCH";
        readonly IssuingCountryMatchesCertificate: "ISSUING_COUNTRY_MATCHES_CERTIFICATE";
        readonly IssuingJurisdictionMatchesCertificate: "ISSUING_JURISDICTION_MATCHES_CERTIFICATE";
    };
    readonly DOCUMENT_FORMAT: {
        readonly DeviceResponseVersionPresence: "DEVICE_RESPONSE_VERSION_PRESENCE";
        readonly DeviceResponseVersionSupported: "DEVICE_RESPONSE_VERSION_SUPPORTED";
        readonly DeviceResponseDocumentPresence: "DEVICE_RESPONSE_DOCUMENT_PRESENCE";
    };
};
export type VerificationAssessment = {
    status: 'PASSED' | 'FAILED' | 'WARNING';
    check: string;
    reason?: string;
} & {
    [C in keyof typeof VerificationAssessmentId]: {
        category: C;
        id: typeof VerificationAssessmentId[C][keyof typeof VerificationAssessmentId[C]];
    };
}[keyof typeof VerificationAssessmentId];
export type VerificationCallback = (item: VerificationAssessment) => void;
export type UserDefinedVerificationCallback = (item: VerificationAssessment, original: VerificationCallback) => void;
export declare const defaultCallback: VerificationCallback;
export declare const buildCallback: (callback?: UserDefinedVerificationCallback) => VerificationCallback;
export declare const onCatCheck: <C extends "ISSUER_AUTH" | "DEVICE_AUTH" | "DATA_INTEGRITY" | "DOCUMENT_FORMAT">(onCheck: UserDefinedVerificationCallback, category: C) => (item: Omit<Extract<{
    status: 'PASSED' | 'FAILED' | 'WARNING';
    check: string;
    reason?: string;
} & {
    category: "ISSUER_AUTH";
    id: "ISSUER_CERTIFICATE_VALIDITY" | "ISSUER_SIGNATURE_VALIDITY" | "MSO_SIGNED_DATE_WITHIN_CERTIFICATE_VALIDITY" | "MSO_VALIDITY_AT_VERIFICATION_TIME" | "ISSUER_SUBJECT_COUNTRY_NAME_PRESENCE";
}, {
    category: C;
}> | Extract<{
    status: 'PASSED' | 'FAILED' | 'WARNING';
    check: string;
    reason?: string;
} & {
    category: "DEVICE_AUTH";
    id: "DOCUMENT_DEVICE_SIGNATURE_PRESENCE" | "DEVICE_AUTH_SIGNATURE_OR_MAC_PRESENCE" | "SESSION_TRANSCRIPT_PROVIDED" | "DEVICE_KEY_AVAILABLE_IN_ISSUERAUTH" | "DEVICE_SIGNATURE_VALIDITY" | "DEVICE_MAC_PRESENCE" | "DEVICE_MAC_ALGORITHM_CORRECTNESS" | "EPHEMERAL_KEY_PRESENCE" | "DEVICE_MAC_VALIDITY";
}, {
    category: C;
}> | Extract<{
    status: 'PASSED' | 'FAILED' | 'WARNING';
    check: string;
    reason?: string;
} & {
    category: "DATA_INTEGRITY";
    id: "ISSUER_AUTH_DIGEST_ALGORITHM_SUPPORTED" | "ISSUER_AUTH_NAMESPACE_DIGEST_PRESENCE" | "ATTRIBUTE_DIGEST_MATCH" | "ISSUING_COUNTRY_MATCHES_CERTIFICATE" | "ISSUING_JURISDICTION_MATCHES_CERTIFICATE";
}, {
    category: C;
}> | Extract<{
    status: 'PASSED' | 'FAILED' | 'WARNING';
    check: string;
    reason?: string;
} & {
    category: "DOCUMENT_FORMAT";
    id: "DEVICE_RESPONSE_VERSION_PRESENCE" | "DEVICE_RESPONSE_VERSION_SUPPORTED" | "DEVICE_RESPONSE_DOCUMENT_PRESENCE";
}, {
    category: C;
}>, "category">) => void;
