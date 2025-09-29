export declare class MDLError extends Error {
    code?: string;
    constructor(message: string, code?: string);
}
export declare class MDLParseError extends Error {
    constructor(message?: string);
}
