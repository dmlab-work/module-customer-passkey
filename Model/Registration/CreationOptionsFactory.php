<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Registration;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\CeremonyFactory;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use DmLab\CustomerPasskey\Model\Webauthn\UserHandle;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Builds the {@see PublicKeyCredentialCreationOptions} handed to
 * `navigator.credentials.create()` for a logged-in customer.
 *
 * The customer entity is the WebAuthn user (no external IdP): the user handle is
 * opaque ({@see UserHandle}), `name` the email and `displayName` the account name. The
 * customer's already-registered passkeys become `excludeCredentials` so the same
 * authenticator cannot enrol twice. Relying-party, timeout, user-verification and
 * authenticator-attachment come from {@see Config}; a resident key is always
 * required because login is discoverable-only.
 */
class CreationOptionsFactory
{
    /** Challenge length in bytes (WebAuthn recommends at least 16). */
    private const CHALLENGE_BYTES = 32;

    /**
     * @param Config $config
     * @param RelyingPartyEntityFactory $relyingPartyEntityFactory
     * @param CredentialSourceRepository $credentialSourceRepository
     * @param UserHandle $userHandle
     */
    public function __construct(
        private readonly Config $config,
        private readonly RelyingPartyEntityFactory $relyingPartyEntityFactory,
        private readonly CredentialSourceRepository $credentialSourceRepository,
        private readonly UserHandle $userHandle
    ) {
    }

    /**
     * Creation options for the given customer, with a fresh random challenge.
     *
     * @param int $customerId owning customer entity id
     * @param string $username account email shown as the credential's `name`
     * @param string $displayName human-friendly account name
     * @param int|string|null $storeId
     */
    public function create(
        int $customerId,
        string $username,
        string $displayName,
        $storeId = null
    ): PublicKeyCredentialCreationOptions {
        $user = PublicKeyCredentialUserEntity::create(
            $username,
            $this->userHandle->forCustomer($customerId),
            $displayName
        );

        return PublicKeyCredentialCreationOptions::create(
            $this->relyingPartyEntityFactory->create($storeId),
            $user,
            random_bytes(self::CHALLENGE_BYTES),
            array_map(
                static fn(int $alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::createPk($alg),
                CeremonyFactory::ALGORITHMS
            ),
            $this->authenticatorSelection($storeId),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            array_map(
                static fn($source) => $source->getPublicKeyCredentialDescriptor(),
                $this->credentialSourceRepository->findAllForCustomer($customerId)
            ),
            $this->config->getTimeout($storeId)
        );
    }

    /**
     * Authenticator-selection criteria from config: attachment ({@see Config}'s
     * "any" maps to no preference), user-verification, and a required resident key
     * (login is discoverable-only, so a non-resident key could never sign in).
     *
     * @param int|string|null $storeId
     */
    private function authenticatorSelection($storeId): AuthenticatorSelectionCriteria
    {
        $attachment = $this->config->getAuthenticatorAttachment($storeId);

        return AuthenticatorSelectionCriteria::create(
            $attachment === Config::ATTACHMENT_ANY ? null : $attachment,
            $this->config->getUserVerification($storeId),
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
        );
    }
}
