/**
 * SSH protocol identification exchange parsing and serialization.
 *
 * @module @neotales/ssh/identification
 */

export {
  formatIdentification,
  parseIdentification,
  readIdentification,
  type SSHIdentification,
  SSHIdentificationError,
  type SSHIdentificationReadResult,
} from "./src/identification.ts";
