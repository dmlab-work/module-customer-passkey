<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Webauthn\UserHandle;
use Magento\Framework\Encryption\EncryptorInterface;
use PHPUnit\Framework\TestCase;

class UserHandleTest extends TestCase
{
    public function testHandleIsKeyedHmacOfCustomerId(): void
    {
        $encryptor = $this->createMock(EncryptorInterface::class);
        $encryptor->expects(self::once())->method('hash')
            ->with('dmlab_customer_passkey_user_handle:42')
            ->willReturn(str_repeat('a', 64));

        $handle = (new UserHandle($encryptor))->forCustomer(42);

        self::assertSame(str_repeat('a', 64), $handle);
        self::assertStringNotContainsString('42', $handle);
    }
}
