<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Registration;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\CeremonyFactory;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialLoader;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use DmLab\CustomerPasskey\Model\Webauthn\UserHandle;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\WebauthnException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Verifies a WebAuthn registration (attestation) response against the challenge
 * the {@see \DmLab\CustomerPasskey\Controller\Register\Options} controller
 * issued, returning the {@see CredentialRecord} to persist.
 *
 * The original creation options are reconstructed from the consumed challenge plus
 * the logged-in customer (the relying party is Magento, so the customer is the
 * WebAuthn user). The library's creation ceremony then enforces challenge match,
 * exact store origin ({@see CeremonyFactory}), RP-ID binding, user
 * presence/verification and a known attestation format; any rejection of the
 * client's response throws a {@see WebauthnException}, which the controller
 * reports generically.
 *
 * This module requests no attestation conveyance (privacy-preserving), so the
 * `none` format is expected; `packed` self-attestation, which clients pass through
 * unchanged, is accepted too ({@see CeremonyFactory}). The client data must be of
 * type `webauthn.create` — the library accepts either ceremony type.
 */
class AttestationVerifier
{
    /** clientDataJSON.type of a registration ceremony (WebAuthn §7.1 step 7). */
    private const CLIENT_DATA_TYPE = 'webauthn.create';

    /**
     * @param RelyingPartyEntityFactory $relyingPartyEntityFactory
     * @param Config $config
     * @param CredentialLoader $credentialLoader
     * @param CeremonyFactory $ceremonyFactory
     * @param UserHandle $userHandle
     */
    public function __construct(
        private readonly RelyingPartyEntityFactory $relyingPartyEntityFactory,
        private readonly Config $config,
        private readonly CredentialLoader $credentialLoader,
        private readonly CeremonyFactory $ceremonyFactory,
        private readonly UserHandle $userHandle
    ) {
    }

    /**
     * Verify the attestation and return the credential source to store.
     *
     * @param int $customerId owning customer entity id
     * @param string $username account email issued as the credential's `name`
     * @param string $displayName human-friendly account name
     * @param string $challenge the raw challenge consumed from the session
     * @param array<string,mixed> $credential decoded browser credential JSON
     * @param int|string|null $storeId
     * @throws WebauthnException when the attestation is invalid (bad/expired challenge,
     *                    origin/RP-ID mismatch, wrong response type, …)
     */
    public function verify(
        int $customerId,
        string $username,
        string $displayName,
        string $challenge,
        array $credential,
        $storeId = null
    ): CredentialRecord {
        $rp = $this->relyingPartyEntityFactory->create($storeId);
        $options = PublicKeyCredentialCreationOptions::create(
            $rp,
            PublicKeyCredentialUserEntity::create($username, $this->userHandle->forCustomer($customerId), $displayName),
            $challenge,
            array_map(
                static fn(int $alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::createPk($alg),
                CeremonyFactory::ALGORITHMS
            ),
            // Carry the configured user-verification requirement: the creation
            // ceremony reads it from authenticatorSelection, so without it a
            // modified client could skip a required PIN/biometric and still pass.
            AuthenticatorSelectionCriteria::create(null, $this->config->getUserVerification($storeId))
        );

        $publicKeyCredential = $this->credentialLoader->load($credential);
        $response = $publicKeyCredential->response;
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw AuthenticatorResponseVerificationException::create(
                'The credential is not a registration (attestation) response.'
            );
        }
        if ($response->clientDataJSON->type !== self::CLIENT_DATA_TYPE) {
            throw AuthenticatorResponseVerificationException::create('The client data type is not "webauthn.create".');
        }

        try {
            return AuthenticatorAttestationResponseValidator::create(
                $this->ceremonyFactory->creationCeremony($storeId)
            )->check($response, $options, (string)$rp->id);
        } catch (WebauthnException $e) {
            throw $e;
        } catch (\Exception $e) {
            // Library decoders throw plain exceptions on malformed client data.
            throw AuthenticatorResponseVerificationException::create('The attestation could not be verified.', $e);
        }
    }
}
