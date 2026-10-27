<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Config;
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
 */
class CeremonyFactory
{
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
     * Library step-manager factory restricted to the store's origins.
     *
     * @param int|string|null $storeId
     */
    private function stepManagerFactory($storeId): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->config->getAllowedOrigins($storeId));

        return $factory;
    }
}
