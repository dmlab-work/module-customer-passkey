<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Helper;

use Magento\Customer\Model\Session;

/**
 * Customer session over a caller-owned array; the parent constructor (session start, storage) is skipped.
 */
class InMemorySession extends Session
{
    /** @var array<string,mixed> */
    private array $slot;

    /**
     * @param array<string,mixed> $slot
     */
    public function __construct(array &$slot)
    {
        $this->slot = &$slot;
    }

    /**
     * @inheritDoc
     */
    public function getData($key = '', $clear = false)
    {
        $value = $this->slot[$key] ?? null;
        if ($clear) {
            unset($this->slot[$key]);
        }
        return $value;
    }

    /**
     * Store a value under the key.
     *
     * @param string $key
     * @param mixed $value
     * @return $this
     */
    public function setData($key, $value)
    {
        $this->slot[$key] = $value;
        return $this;
    }

    /**
     * Remove the key.
     *
     * @param string $key
     * @return $this
     */
    public function unsetData($key)
    {
        unset($this->slot[$key]);
        return $this;
    }
}
