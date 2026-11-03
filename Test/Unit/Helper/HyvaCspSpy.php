<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Helper;

/**
 * Stand-in for Hyvä's `$hyvaCsp` view model that counts inline-script registrations.
 */
class HyvaCspSpy
{
    /** @var int */
    public int $calls = 0;

    /**
     * Record one inline-script registration.
     */
    public function registerInlineScript(): void
    {
        $this->calls++;
    }
}
