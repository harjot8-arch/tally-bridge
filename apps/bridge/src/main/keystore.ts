/**
 * The keystore.
 *
 * WHAT LIVES HERE, AND WHAT DELIBERATELY DOES NOT.
 *
 * Electron's safeStorage wraps a per-app key with the OS keychain — DPAPI on Windows, Keychain
 * on macOS. It is NOT a vault. Electron's own docs are explicit: contents are protected from
 * OTHER USERS on the machine, not from other processes running as the SAME user. Any process
 * running as that Windows user can call CryptUnprotectData and read this back. That is exactly
 * the VS Code / Slack / Signal token-theft class of attack, and it is not theoretical.
 *
 * So the rule is: only keep something here whose theft is SURVIVABLE and REVOCABLE.
 *
 *   STORED  Ed25519 device SIGNING key. Steal it and you can upload garbage until the owner
 *           clicks "revoke device" — then you have nothing. It never decrypted anything.
 *
 *   STORED  The identity PUBLIC key. It is public. It cannot read data. Its theft is a non-event.
 *
 *   STORED  wrapped_idSK_device, ONLY when the owner opts in to "remember on this PC", and by
 *           default only on the Tally host — where it leaks nothing Tally does not already leak
 *           in plaintext on the same disk.
 *
 *   NEVER   A bare identity SECRET key. Theft would decrypt the entire server history, and
 *           there is no undo. That asymmetry against the signing key is the whole argument.
 *
 *   NEVER   The user's passphrase, in any form.
 */

import { HumanError } from './errors.ts';

/** The slice of Electron's safeStorage we depend on. Injected so this is testable and portable. */
export interface SafeStorageLike {
  isEncryptionAvailable(): boolean;
  encryptString(plainText: string): Buffer;
  decryptString(encrypted: Buffer): string;
}

/** Persistence. Injected so tests don't touch disk and so the backing store can change. */
export interface KeystoreBackend {
  read(key: string): Buffer | undefined;
  write(key: string, value: Buffer): void;
  delete(key: string): void;
  has(key: string): boolean;
}

/**
 * Extends HumanError because this message is written FOR the owner — it names the Windows
 * service they have to turn back on. That inheritance is what lets `humanError` show it
 * verbatim; an error that does not claim a human audience gets the generic sentence instead.
 */
export class KeystoreUnavailableError extends HumanError {
  constructor() {
    super(
      'This computer cannot store the app securely. On Windows this usually means the ' +
        'Credential Manager service is disabled.',
    );
    this.name = 'KeystoreUnavailableError';
  }
}

const K = {
  deviceId: 'device.id',
  deviceSecret: 'device.sk',
  devicePublic: 'device.pk',
  identityPublic: 'identity.pk',
  tenantId: 'tenant.id',
  wrappedIdentityDevice: 'identity.wrapped.device',
  wrappedIdentityPass: 'identity.wrapped.pass',
  serverUrl: 'server.url',
  seq: 'device.seq',
} as const;

export class Keystore {
  private readonly safe: SafeStorageLike;
  private readonly backend: KeystoreBackend;

  constructor(safe: SafeStorageLike, backend: KeystoreBackend) {
    // HARD-FAIL, and never fall back to a plaintext file.
    //
    // A fallback here would be the worst possible outcome: the app keeps working, nobody
    // notices, and the device key sits unprotected on disk. Refusing to start is loud, and
    // loud is correct — an owner who cannot set up is a support call; an owner whose key is
    // silently in the clear is a breach.
    if (!safe.isEncryptionAvailable()) throw new KeystoreUnavailableError();
    this.safe = safe;
    this.backend = backend;
  }

  private putString(key: string, value: string): void {
    this.backend.write(key, this.safe.encryptString(value));
  }

  private getString(key: string): string | undefined {
    const raw = this.backend.read(key);
    if (!raw) return undefined;
    try {
      return this.safe.decryptString(raw);
    } catch {
      // The OS key changed (Windows profile reset, restored to a different machine) so this
      // blob is undecryptable forever. Treat it as absent: the app re-pairs the device, which
      // is a 6-digit code, rather than wedging on a permanently unreadable file.
      return undefined;
    }
  }

  private putBytes(key: string, value: Uint8Array): void {
    this.putString(key, Buffer.from(value).toString('base64'));
  }

  private getBytes(key: string): Uint8Array | undefined {
    const s = this.getString(key);
    return s === undefined ? undefined : new Uint8Array(Buffer.from(s, 'base64'));
  }

  // ------------------------------------------------------------------ device identity

  isProvisioned(): boolean {
    return this.backend.has(K.deviceSecret) && this.backend.has(K.identityPublic);
  }

  setDevice(deviceId: string, publicKey: Uint8Array, secretKey: Uint8Array): void {
    this.putString(K.deviceId, deviceId);
    this.putBytes(K.devicePublic, publicKey);
    this.putBytes(K.deviceSecret, secretKey);
  }

  getDeviceId(): string | undefined {
    return this.getString(K.deviceId);
  }

  getDeviceSecretKey(): Uint8Array | undefined {
    return this.getBytes(K.deviceSecret);
  }

  getDevicePublicKey(): Uint8Array | undefined {
    return this.getBytes(K.devicePublic);
  }

  // ------------------------------------------------------------------ identity (public only)

  /**
   * The identity PUBLIC key — everything the Bridge needs to seal an upload, and nothing more.
   *
   * There is no setIdentitySecretKey on this class, and that absence is deliberate: the type
   * system should make the wrong thing unwritable, not merely discouraged.
   */
  setIdentityPublicKey(pk: Uint8Array): void {
    this.putBytes(K.identityPublic, pk);
  }

  getIdentityPublicKey(): Uint8Array | undefined {
    return this.getBytes(K.identityPublic);
  }

  // ------------------------------------------------------------------ opt-in device unlock

  /**
   * "Remember on this PC" — the wrapped identity secret.
   *
   * Only ever set this after an explicit, explained user choice. It is defensible on the Tally
   * host (where Tally's own plaintext sits on the same disk anyway) and it is what resolves
   * ~90% of real recovery cases — the owner who set a passphrase once and needs the dashboard
   * eight months later.
   */
  setWrappedIdentityForDevice(blobJson: string): void {
    this.putString(K.wrappedIdentityDevice, blobJson);
  }

  getWrappedIdentityForDevice(): string | undefined {
    return this.getString(K.wrappedIdentityDevice);
  }

  forgetWrappedIdentity(): void {
    this.backend.delete(K.wrappedIdentityDevice);
  }

  // ------------------------------------------------------------------ local unlock (passphrase)

  /**
   * The PASSPHRASE-wrapped identity — what the local dashboard's unlock opens.
   *
   * Storing this does not violate the "NEVER a bare identity secret key" rule above, and the
   * distinction is worth stating precisely: this blob is XChaCha20-Poly1305 ciphertext under a
   * KEK derived by Argon2id (64 MiB) from a passphrase this machine never stores. Stealing it
   * buys an offline guessing attack priced at ~half a second per guess — the same exposure as
   * the copy the SERVER already stores, which is the identical blob. What it removes is the
   * network from the unlock path: the desktop dashboard opens with local data and a passphrase,
   * and a server that withholds the blob cannot lock the owner out of their own machine.
   *
   * It also does not extend safeStorage's job description: safeStorage here is an outer layer
   * over ciphertext that is already sealed against everyone who lacks the passphrase.
   */
  setWrappedIdentityForPassphrase(blobJson: string): void {
    this.putString(K.wrappedIdentityPass, blobJson);
  }

  getWrappedIdentityForPassphrase(): string | undefined {
    return this.getString(K.wrappedIdentityPass);
  }

  // ------------------------------------------------------------------ config

  setTenantId(t: string): void {
    this.putString(K.tenantId, t);
  }

  getTenantId(): string | undefined {
    return this.getString(K.tenantId);
  }

  setServerUrl(u: string): void {
    this.putString(K.serverUrl, u);
  }

  getServerUrl(): string | undefined {
    return this.getString(K.serverUrl);
  }

  // ------------------------------------------------------------------ seq

  /**
   * The AAD sequence counter.
   *
   * Persisted so gaps are visible to the server. Note what this is NOT: a nonce. The AEAD nonce
   * is 192 bits of randomness precisely so that this counter rolling backward — backup restore,
   * cloned PC, force-kill — is a non-event rather than a key-recovery break. Under AES-GCM the
   * same rollback would be catastrophic; that is why XChaCha20 was chosen.
   */
  getSeq(): number {
    const s = this.getString(K.seq);
    const n = s === undefined ? 0 : Number(s);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  }

  setSeq(n: number): void {
    this.putString(K.seq, String(n));
  }

  /** Full local reset. Used by "Reset dashboard" — the third recovery path. */
  wipe(): void {
    for (const k of Object.values(K)) this.backend.delete(k);
  }
}
