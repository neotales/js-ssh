/** Error raised when an SSH key or signature value is malformed. */
export class SSHKeyError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "SSHKeyError";
    }
}
