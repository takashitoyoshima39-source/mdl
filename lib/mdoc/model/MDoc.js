"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MDoc = exports.MDocStatus = void 0;
const cbor_1 = require("../../cbor");
var MDocStatus;
(function (MDocStatus) {
    MDocStatus[MDocStatus["OK"] = 0] = "OK";
    MDocStatus[MDocStatus["GeneralError"] = 10] = "GeneralError";
    MDocStatus[MDocStatus["CBORDecodingError"] = 11] = "CBORDecodingError";
    MDocStatus[MDocStatus["CBORValidationError"] = 12] = "CBORValidationError";
})(MDocStatus || (exports.MDocStatus = MDocStatus = {}));
class MDoc {
    constructor(documents = [], version = '1.0', status = MDocStatus.OK, documentErrors = []) {
        this.documents = documents;
        this.version = version;
        this.status = status;
        this.documentErrors = documentErrors;
    }
    addDocument(document) {
        if (typeof document.issuerSigned === 'undefined') {
            throw new Error('Cannot add an unsigned document');
        }
        this.documents.push(document);
    }
    encode() {
        return (0, cbor_1.cborEncode)({
            version: this.version,
            documents: this.documents.map((doc) => doc.prepare()),
            status: this.status,
        });
    }
}
exports.MDoc = MDoc;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTURvYy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tZG9jL21vZGVsL01Eb2MudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEscUNBQXdDO0FBU3hDLElBQVksVUFLWDtBQUxELFdBQVksVUFBVTtJQUNwQix1Q0FBTSxDQUFBO0lBQ04sNERBQWlCLENBQUE7SUFDakIsc0VBQXNCLENBQUE7SUFDdEIsMEVBQXdCLENBQUE7QUFDMUIsQ0FBQyxFQUxXLFVBQVUsMEJBQVYsVUFBVSxRQUtyQjtBQUVELE1BQWEsSUFBSTtJQUNmLFlBQ2tCLFlBQW9DLEVBQUUsRUFDdEMsVUFBVSxLQUFLLEVBQ2YsU0FBcUIsVUFBVSxDQUFDLEVBQUUsRUFDbEMsaUJBQWtDLEVBQUU7UUFIcEMsY0FBUyxHQUFULFNBQVMsQ0FBNkI7UUFDdEMsWUFBTyxHQUFQLE9BQU8sQ0FBUTtRQUNmLFdBQU0sR0FBTixNQUFNLENBQTRCO1FBQ2xDLG1CQUFjLEdBQWQsY0FBYyxDQUFzQjtJQUNsRCxDQUFDO0lBRUwsV0FBVyxDQUFDLFFBQThCO1FBQ3hDLElBQUksT0FBTyxRQUFRLENBQUMsWUFBWSxLQUFLLFdBQVcsRUFBRTtZQUNoRCxNQUFNLElBQUksS0FBSyxDQUFDLGlDQUFpQyxDQUFDLENBQUM7U0FDcEQ7UUFDRCxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxRQUFnQyxDQUFDLENBQUM7SUFDeEQsQ0FBQztJQUVELE1BQU07UUFDSixPQUFPLElBQUEsaUJBQVUsRUFBQztZQUNoQixPQUFPLEVBQUUsSUFBSSxDQUFDLE9BQU87WUFDckIsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxHQUFHLENBQUMsT0FBTyxFQUFFLENBQUM7WUFDckQsTUFBTSxFQUFFLElBQUksQ0FBQyxNQUFNO1NBQ3BCLENBQUMsQ0FBQztJQUNMLENBQUM7Q0FDRjtBQXRCRCxvQkFzQkMifQ==