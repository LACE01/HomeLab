// Browser-side WebAuthn (#67): converts the server's base64url options into the
// ArrayBuffers navigator.credentials needs, drives the ceremony, and serializes the
// authenticator's response back into the base64url JSON py_webauthn verifies.
// Hand-rolled (no @simplewebauthn/browser dep) to keep the bundle lean.

function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function webauthnSupported() {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

export async function startRegistration(optionsJSON) {
  const publicKey = {
    ...optionsJSON,
    challenge: b64urlToBuf(optionsJSON.challenge),
    user: { ...optionsJSON.user, id: b64urlToBuf(optionsJSON.user.id) },
    excludeCredentials: (optionsJSON.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
  const cred = await navigator.credentials.create({ publicKey });
  return {
    id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      attestationObject: bufToB64url(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
  };
}

export async function startAuthentication(optionsJSON) {
  const publicKey = {
    ...optionsJSON,
    challenge: b64urlToBuf(optionsJSON.challenge),
    allowCredentials: (optionsJSON.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
  const cred = await navigator.credentials.get({ publicKey });
  return {
    id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      authenticatorData: bufToB64url(cred.response.authenticatorData),
      signature: bufToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : undefined,
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
  };
}
