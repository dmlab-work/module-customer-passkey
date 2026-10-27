<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use Magento\Framework\Encryption\EncryptorInterface;

/**
 * Opaque WebAuthn user handle for a customer (WebAuthn §14.6.1): an HMAC of the
 * customer id under the deployment key, 64 bytes, carrying no PII and not
 * enumerable. Stable per customer, so options and verify agree without state.
 *
 * Each credential stores the handle it was registered with, so rotating the key
 * only changes the handle of later registrations; legacy credentials (no stored
 * handle) keep the customer id they were enrolled with.
 */
class UserHandle
{
    /** Domain separator so the HMAC is not reusable for other purposes. */
    private const CONTEXT = 'dmlab_customer_passkey_user_handle:';

    /**
     * @param EncryptorInterface $encryptor
     */
    public function __construct(
        private readonly EncryptorInterface $encryptor
    ) {
    }

    /**
     * The user handle new registrations of this customer are issued with.
     *
     * @param int $customerId
     */
    public function forCustomer(int $customerId): string
    {
        return $this->encryptor->hash(self::CONTEXT . $customerId);
    }
}
