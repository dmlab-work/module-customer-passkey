<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithms;
use DmLab\CustomerPasskey\Model\Config;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

/**
 * Builds the library's creation/request ceremonies for a store, shared by the
 * attestation and assertion verifiers.
 *
 * The origin step is {@see \Webauthn\CeremonyStep\CheckAllowedOrigins} over the
 * store's exact origins ({@see Config::getAllowedOrigins}), subdomains off. Without
 * an allow-list the library falls back to the deprecated `CheckOrigin`, which
 * accepts any subdomain of the RP ID on any port.
 *
 * Signature algorithms are ES256, EdDSA (Ed25519, needs ext-sodium) and RS256.
 * Attestation formats are `none` plus `packed`: under "none" conveyance a client
 * passes packed self-attestation through unchanged (WebAuthn §5.1.3 step 23).
 */
class CeremonyFactory
{
    /** COSE algorithms offered and accepted, most preferred first. */
    public const ALGORITHMS = [
        Algorithms::COSE_ALGORITHM_ES256,
        Algorithms::COSE_ALGORITHM_EDDSA,
        Algorithms::COSE_ALGORITHM_RS256,
    ];

    /**
     * @param Config $config
     */
    public function __construct(
        private readonly Config $config
    ) {
    }

    /**
     * Registration (attestation) ceremony for the store.
     *
     * @param int|string|null $storeId
     */
    public function creationCeremony($storeId = null): CeremonyStepManager
    {
        return $this->stepManagerFactory($storeId)->creationCeremony();
    }

    /**
     * Authentication (assertion) ceremony for the store.
     *
     * @param int|string|null $storeId
     */
    public function requestCeremony($storeId = null): CeremonyStepManager
    {
        return $this->stepManagerFactory($storeId)->requestCeremony();
    }

    /**
     * Signature algorithms matching {@see self::ALGORITHMS}.
     */
    public function algorithmManager(): Manager
    {
        return Manager::create()->add(ES256::create(), Ed25519::create(), RS256::create());
    }

    /**
     * Attestation statement formats accepted at registration (`none` is always included).
     */
    public function attestationStatementSupportManager(): AttestationStatementSupportManager
    {
        return AttestationStatementSupportManager::create([
            PackedAttestationStatementSupport::create($this->algorithmManager()),
        ]);
    }

    /**
     * Library step-manager factory restricted to the store's origins.
     *
     * @param int|string|null $storeId
     */
    private function stepManagerFactory($storeId): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->config->getAllowedOrigins($storeId));
        $factory->setAlgorithmManager($this->algorithmManager());
        $factory->setAttestationStatementSupportManager($this->attestationStatementSupportManager());

        return $factory;
    }
}
