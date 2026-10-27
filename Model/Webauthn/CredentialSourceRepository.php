<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use Magento\Framework\Stdlib\DateTime\DateTime;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Maps our credential storage ({@see CredentialRepository}) to the library's
 * {@see CredentialRecord} so the attestation and assertion ceremonies read and
 * write credentials through our table.
 *
 * Type mapping between the two worlds:
 *  - the library uses raw binary ids/keys; we persist the credential id as
 *    base64url and the COSE public key as base64;
 *  - the WebAuthn user handle is stored per credential ({@see UserHandle}); rows
 *    without one were registered with the owning customer id as handle;
 *  - the owning customer is the row's `customer_id`, never derived from the handle;
 *  - backup eligibility/state and uvInitialized are kept for the next ceremony;
 *  - the AAGUID is a {@see Uuid}; the all-zero (nil) AAGUID is stored as null.
 *
 * The stored columns are library-agnostic, so rows written under webauthn-lib 4.x
 * load unchanged.
 */
class CredentialSourceRepository
{
    /** AAGUID emitted by authenticators that withhold one; stored as null. */
    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';

    /** Any 16-byte value in 8-4-4-4-12 hex form; AAGUIDs need not carry the RFC 4122 variant. */
    private const AAGUID_PATTERN = '/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/Di';

    /**
     * @param CredentialRepository $credentials
     * @param DateTime $dateTime
     */
    public function __construct(
        private readonly CredentialRepository $credentials,
        private readonly DateTime $dateTime
    ) {
    }

    /**
     * The stored credential for a raw credential id, or null when unknown.
     *
     * @param string $publicKeyCredentialId raw credential id bytes
     */
    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        $credential = $this->credentials->findByCredentialId($this->encodeBase64Url($publicKeyCredentialId));

        return $credential === null ? null : $this->toSource($credential);
    }

    /**
     * The owning customer id of a raw credential id, or null when unknown.
     *
     * @param string $publicKeyCredentialId raw credential id bytes
     */
    public function findCustomerIdByCredentialId(string $publicKeyCredentialId): ?int
    {
        return $this->credentials->findByCredentialId($this->encodeBase64Url($publicKeyCredentialId))?->customerId;
    }

    /**
     * All stored credentials of a customer.
     *
     * @param int $customerId
     * @return CredentialRecord[]
     */
    public function findAllForCustomer(int $customerId): array
    {
        if ($customerId <= 0) {
            return [];
        }

        return array_map(
            fn(Credential $credential): CredentialRecord => $this->toSource($credential),
            $this->credentials->listByCustomer($customerId)
        );
    }

    /**
     * Persist a credential after a successful assertion (fresh counter, flags, last use).
     *
     * A no-op when the row is gone (revoked mid-ceremony): it is never re-created here.
     *
     * @param CredentialRecord $publicKeyCredentialSource
     */
    public function saveCredentialSource(CredentialRecord $publicKeyCredentialSource): void
    {
        $credentialId = $this->encodeBase64Url($publicKeyCredentialSource->publicKeyCredentialId);
        $existing = $this->credentials->findByCredentialId($credentialId);
        if ($existing === null) {
            return;
        }

        $credential = $this->toCredential($publicKeyCredentialSource, $existing);
        // This is the assertion (login) write path; stamp the last successful use.
        $credential->lastUsedAt = $this->dateTime->gmtDate();

        $this->credentials->save($credential);
    }

    /**
     * Persist a freshly attested credential, applying the optional enrol-time label.
     *
     * The assertion write path ({@see saveCredentialSource}) is label-agnostic; this
     * is the registration entry point, so it records the customer-chosen label on
     * the new row together with the user handle it was registered with. A new row
     * is always created.
     *
     * @param CredentialRecord $source
     * @param int $customerId owning customer entity id
     * @param string|null $label
     * @throws \Magento\Framework\DB\Adapter\DuplicateException when the credential id is already stored
     */
    public function saveNewCredential(CredentialRecord $source, int $customerId, ?string $label = null): Credential
    {
        $credential = $this->toCredential($source, new Credential(customerId: $customerId));
        $credential->userHandle = $this->encodeBase64Url($source->userHandle);
        if ($label !== null && $label !== '') {
            $credential->label = $label;
        }

        return $this->credentials->save($credential);
    }

    /**
     * Map a stored credential to the library record used by the validators.
     *
     * @param Credential $credential
     */
    private function toSource(Credential $credential): CredentialRecord
    {
        // Not Uuid::isValid(): it rejects non-RFC-4122-variant AAGUIDs, which would then be saved back as null.
        $aaguid = $credential->aaguid !== null && preg_match(self::AAGUID_PATTERN, $credential->aaguid) === 1
            ? Uuid::fromString($credential->aaguid)
            : Uuid::fromString(self::NIL_AAGUID);

        return CredentialRecord::create(
            $this->decodeBase64Url($credential->credentialId),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $credential->transports,
            $credential->attestationType ?? 'none',
            EmptyTrustPath::create(),
            $aaguid,
            $this->decodeBase64($credential->publicKey),
            $credential->userHandle !== null
                ? $this->decodeBase64Url($credential->userHandle)
                : (string)$credential->customerId,
            $credential->signCount,
            null,
            $credential->backupEligible,
            $credential->backupStatus,
            // Unknown (legacy row) as false, so the next verified assertion records it.
            $credential->uvInitialized ?? false
        );
    }

    /**
     * Merge a library record into a stored credential.
     *
     * The owning customer, user handle, label and creation time are kept; the
     * counter, flags and mutable attestation fields are refreshed.
     *
     * @param CredentialRecord $source
     * @param Credential $credential
     */
    private function toCredential(CredentialRecord $source, Credential $credential): Credential
    {
        $credential->credentialId = $this->encodeBase64Url($source->publicKeyCredentialId);
        $credential->publicKey = $this->encodeBase64($source->credentialPublicKey);
        $credential->signCount = $source->counter;
        $credential->transports = $source->transports;
        $credential->attestationType = $source->attestationType;
        $credential->backupEligible = $source->backupEligible;
        $credential->backupStatus = $source->backupStatus;
        $credential->uvInitialized = $source->uvInitialized;

        $aaguid = $source->aaguid->toRfc4122();
        $credential->aaguid = $aaguid === self::NIL_AAGUID ? null : $aaguid;

        return $credential;
    }

    /**
     * Encode raw bytes as unpadded base64url (our stored credential-id form).
     *
     * @param string $raw
     */
    private function encodeBase64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Decode an unpadded base64url string back to raw bytes.
     *
     * @param string $value
     */
    private function decodeBase64Url(string $value): string
    {
        return (string)base64_decode(strtr($value, '-_', '+/'), true);
    }

    /**
     * Encode raw COSE key bytes as base64 (our stored public-key form).
     *
     * @param string $raw
     */
    private function encodeBase64(string $raw): string
    {
        return base64_encode($raw);
    }

    /**
     * Decode a base64 string back to raw bytes.
     *
     * @param string $value
     */
    private function decodeBase64(string $value): string
    {
        return (string)base64_decode($value, true);
    }
}
