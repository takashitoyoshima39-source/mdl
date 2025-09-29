"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DataItem = exports.cborEncode = exports.cborDecode = exports.setCborEncodeDecodeOptions = exports.getCborEncodeDecodeOptions = exports.DateOnly = void 0;
const cbor_x_1 = require("cbor-x");
const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');
class DateOnly extends Date {
    constructor(strDate) {
        super(strDate);
    }
    get [Symbol.toStringTag]() {
        return DateOnly.name;
    }
    toISOString() {
        return super.toISOString().split('T')[0];
    }
    toString() {
        return this.toISOString();
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    toJSON(key) {
        return this.toISOString();
    }
    [customInspectSymbol]() {
        return this.toISOString();
    }
}
exports.DateOnly = DateOnly;
let encoderDefaults = {
    tagUint8Array: false,
    useRecords: false,
    mapsAsObjects: false,
    // @ts-ignore
    useTag259ForMaps: false,
    variableMapSize: true,
};
// tdate data item shall contain a date-time string as specified in RFC 3339 (with no fraction of seconds)
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
(0, cbor_x_1.addExtension)({
    Class: Date,
    tag: 0,
    encode: (date, encode) => encode(`${date.toISOString().split('.')[0]}Z`),
    decode: (isoStringDateTime) => new Date(isoStringDateTime),
});
// full-date data item shall contain a full-date string as specified in RFC 3339
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
(0, cbor_x_1.addExtension)({
    Class: DateOnly,
    tag: 1004,
    encode: (date, encode) => encode(date.toISOString()),
    decode: (isoStringDate) => new DateOnly(isoStringDate),
});
const getCborEncodeDecodeOptions = () => {
    return encoderDefaults;
};
exports.getCborEncodeDecodeOptions = getCborEncodeDecodeOptions;
const setCborEncodeDecodeOptions = (options) => {
    encoderDefaults = options;
};
exports.setCborEncodeDecodeOptions = setCborEncodeDecodeOptions;
const cborDecode = (input, options = encoderDefaults) => {
    const params = { ...encoderDefaults, ...options };
    const enc = new cbor_x_1.Encoder(params);
    return enc.decode(input);
};
exports.cborDecode = cborDecode;
const cborEncode = (obj, options = encoderDefaults) => {
    const params = { ...encoderDefaults, ...options };
    const enc = new cbor_x_1.Encoder(params);
    return enc.encode(obj);
};
exports.cborEncode = cborEncode;
var DataItem_1 = require("./DataItem");
Object.defineProperty(exports, "DataItem", { enumerable: true, get: function () { return DataItem_1.DataItem; } });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvY2Jvci9pbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSxtQ0FJZ0I7QUFFaEIsTUFBTSxtQkFBbUIsR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFDLDRCQUE0QixDQUFDLENBQUM7QUFFckUsTUFBYSxRQUFTLFNBQVEsSUFBSTtJQUNoQyxZQUFZLE9BQWdCO1FBQzFCLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUNqQixDQUFDO0lBRUQsSUFBSSxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUM7UUFDdEIsT0FBTyxRQUFRLENBQUMsSUFBSSxDQUFDO0lBQ3ZCLENBQUM7SUFFRCxXQUFXO1FBQ1QsT0FBTyxLQUFLLENBQUMsV0FBVyxFQUFFLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQzNDLENBQUM7SUFFRCxRQUFRO1FBQ04sT0FBTyxJQUFJLENBQUMsV0FBVyxFQUFFLENBQUM7SUFDNUIsQ0FBQztJQUVELDZEQUE2RDtJQUM3RCxNQUFNLENBQUMsR0FBUztRQUNkLE9BQU8sSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBQzVCLENBQUM7SUFFRCxDQUFDLG1CQUFtQixDQUFDO1FBQ25CLE9BQU8sSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBQzVCLENBQUM7Q0FDRjtBQXpCRCw0QkF5QkM7QUFFRCxJQUFJLGVBQWUsR0FBWTtJQUM3QixhQUFhLEVBQUUsS0FBSztJQUNwQixVQUFVLEVBQUUsS0FBSztJQUNqQixhQUFhLEVBQUUsS0FBSztJQUNwQixhQUFhO0lBQ2IsZ0JBQWdCLEVBQUUsS0FBSztJQUN2QixlQUFlLEVBQUUsSUFBSTtDQUN0QixDQUFDO0FBRUYsMEdBQTBHO0FBQzFHLGdFQUFnRTtBQUNoRSxJQUFBLHFCQUFZLEVBQUM7SUFDWCxLQUFLLEVBQUUsSUFBSTtJQUNYLEdBQUcsRUFBRSxDQUFDO0lBQ04sTUFBTSxFQUFFLENBQUMsSUFBVSxFQUFFLE1BQU0sRUFBRSxFQUFFLENBQUMsTUFBTSxDQUFDLEdBQUcsSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDO0lBQzlFLE1BQU0sRUFBRSxDQUFDLGlCQUFzQixFQUFFLEVBQUUsQ0FBQyxJQUFJLElBQUksQ0FBQyxpQkFBaUIsQ0FBQztDQUNoRSxDQUFDLENBQUM7QUFFSCxnRkFBZ0Y7QUFDaEYsZ0VBQWdFO0FBQ2hFLElBQUEscUJBQVksRUFBQztJQUNYLEtBQUssRUFBRSxRQUFRO0lBQ2YsR0FBRyxFQUFFLElBQUk7SUFDVCxNQUFNLEVBQUUsQ0FBQyxJQUFjLEVBQUUsTUFBTSxFQUFFLEVBQUUsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBQzlELE1BQU0sRUFBRSxDQUFDLGFBQWtCLEVBQVUsRUFBRSxDQUFDLElBQUksUUFBUSxDQUFDLGFBQWEsQ0FBQztDQUNwRSxDQUFDLENBQUM7QUFFSSxNQUFNLDBCQUEwQixHQUFHLEdBQWEsRUFBRTtJQUN2RCxPQUFPLGVBQWUsQ0FBQztBQUN6QixDQUFDLENBQUM7QUFGVyxRQUFBLDBCQUEwQiw4QkFFckM7QUFFSyxNQUFNLDBCQUEwQixHQUFHLENBQUMsT0FBZ0IsRUFBUyxFQUFFO0lBQ3BFLGVBQWUsR0FBRyxPQUFPLENBQUM7QUFDNUIsQ0FBQyxDQUFDO0FBRlcsUUFBQSwwQkFBMEIsOEJBRXJDO0FBRUssTUFBTSxVQUFVLEdBQUcsQ0FDeEIsS0FBMEIsRUFDMUIsVUFBbUIsZUFBZSxFQUM3QixFQUFFO0lBQ1AsTUFBTSxNQUFNLEdBQUcsRUFBRSxHQUFHLGVBQWUsRUFBRSxHQUFHLE9BQU8sRUFBRSxDQUFDO0lBQ2xELE1BQU0sR0FBRyxHQUFHLElBQUksZ0JBQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUNoQyxPQUFPLEdBQUcsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUM7QUFDM0IsQ0FBQyxDQUFDO0FBUFcsUUFBQSxVQUFVLGNBT3JCO0FBRUssTUFBTSxVQUFVLEdBQUcsQ0FDeEIsR0FBWSxFQUNaLFVBQW1CLGVBQWUsRUFDMUIsRUFBRTtJQUNWLE1BQU0sTUFBTSxHQUFHLEVBQUUsR0FBRyxlQUFlLEVBQUUsR0FBRyxPQUFPLEVBQUUsQ0FBQztJQUNsRCxNQUFNLEdBQUcsR0FBRyxJQUFJLGdCQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDaEMsT0FBTyxHQUFHLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ3pCLENBQUMsQ0FBQztBQVBXLFFBQUEsVUFBVSxjQU9yQjtBQUVGLHVDQUFzQztBQUE3QixvR0FBQSxRQUFRLE9BQUEifQ==