<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Authentication;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\CeremonyFactory;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialLoader;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\WebauthnException;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Verifies a WebAuthn authentication (assertion) response against the challenge
 * the {@see \DmLab\CustomerPasskey\Controller\Login\Options} controller
 * issued, returning the {@see CredentialRecord} whose owning customer id
 * ({@see CredentialRecord::$userHandle}) the caller logs in.
 *
 * The stored credential is resolved by the asserted credential id through our
 * storage ({@see CredentialSourceRepository}); an unknown id is rejected before
 * any cryptographic work. The library's request ceremony then enforces challenge
 * match, exact store origin ({@see CeremonyFactory}), RP-ID binding, user
 * presence/verification, the signature against the stored public key, and the
 * sign counter — a counter that did not advance is a cloned authenticator and
 * throws. On success the source carries the fresh counter for the caller to persist.
 *
 * Every rejection of the client's response is a {@see WebauthnException}; anything
 * else escaping {@see verify()} is a server fault.
 */
class AssertionVerifier
{
    /**
     * @param Config $config
     * @param RelyingPartyEntityFactory $relyingPartyEntityFactory
     * @param CredentialSourceRepository $credentialSourceRepository
     * @param CredentialLoader $credentialLoader
     * @param CeremonyFactory $ceremonyFactory
     */
    public function __construct(
        private readonly Config $config,
        private readonly RelyingPartyEntityFactory $relyingPartyEntityFactory,
        private readonly CredentialSourceRepository $credentialSourceRepository,
        private readonly CredentialLoader $credentialLoader,
        private readonly CeremonyFactory $ceremonyFactory
    ) {
    }

    /**
     * Verify the assertion and return the authenticated credential source.
     *
     * @param string $challenge the raw challenge consumed from the session
     * @param array<string,mixed> $credential decoded browser credential JSON
     * @param int|null $expectedCustomerId the account an email-first request was
     *                 scoped to (0 = unknown email, rejects everything); null for an
     *                 unscoped discoverable request, which accepts any resident key
     * @param int|string|null $storeId
     * @throws WebauthnException when the assertion is invalid (bad/expired challenge,
     *                    origin/RP-ID mismatch, unknown credential, credential not
     *                    owned by the scoped account, bad signature, counter
     *                    regression, …)
     */
    public function verify(
        string $challenge,
        array $credential,
        ?int $expectedCustomerId = null,
        $storeId = null
    ): CredentialRecord {
        $rp = $this->relyingPartyEntityFactory->create($storeId);
        $rpId = (string)$rp->id;

        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            $rpId === '' ? null : $rpId,
            [],
            $this->config->getUserVerification($storeId),
            $this->config->getTimeout($storeId)
        );

        $publicKeyCredential = $this->credentialLoader->load($credential);
        $response = $publicKeyCredential->response;
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw AuthenticatorResponseVerificationException::create(
                'The credential is not an authentication (assertion) response.'
            );
        }

        $source = $this->credentialSourceRepository->findOneByCredentialId($publicKeyCredential->rawId);
        if ($source === null) {
            throw AuthenticatorResponseVerificationException::create('The credential is not registered.');
        }

        // Email-first request: the credential must belong to the scoped account.
        // An empty library allowCredentials list is not enforced by the request
        // ceremony, so this is checked here — it is also what makes disabling
        // passwordless login effective server-side (an unknown email scopes to 0).
        if ($expectedCustomerId !== null && (int)$source->userHandle !== $expectedCustomerId) {
            throw AuthenticatorResponseVerificationException::create(
                'The credential does not belong to the requested account.'
            );
        }

        try {
            return AuthenticatorAssertionResponseValidator::create(
                $this->ceremonyFactory->requestCeremony($storeId)
            )->check(
                $source,
                $response,
                $options,
                $rpId,
                $source->userHandle
            );
        } catch (WebauthnException $e) {
            throw $e;
        } catch (\Exception $e) {
            // E.g. a malformed DER signature fails in the ECDSA decoder with a plain InvalidArgumentException.
            throw AuthenticatorResponseVerificationException::create('The assertion could not be verified.', $e);
        }
    }
}
