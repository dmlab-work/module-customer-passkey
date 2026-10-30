<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Security;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Security\RecentAuthentication;
use DmLab\CustomerPasskey\Test\Unit\Helper\InMemorySession;
use Magento\Customer\Model\AuthenticationInterface;
use Magento\Framework\Exception\InvalidEmailOrPasswordException;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\Exception\State\UserLockedException;
use Magento\Framework\Phrase;
use Magento\Framework\Stdlib\DateTime\DateTime;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

#[AllowMockObjectsWithoutExpectations]
class RecentAuthenticationTest extends TestCase
{
    private const NOW = 1_800_000_000;

    /** @var array<string,mixed> */
    private array $store = [];

    /** @var AuthenticationInterface&MockObject */
    private $authentication;

    /** @var LoggerInterface&MockObject */
    private $logger;

    /** @var RecentAuthentication */
    private RecentAuthentication $recent;

    protected function setUp(): void
    {
        $this->store = [];

        $session = new InMemorySession($this->store);

        $config = $this->createStub(Config::class);
        $config->method('getReauthWindow')->willReturn(300);

        $dateTime = $this->createStub(DateTime::class);
        $dateTime->method('gmtTimestamp')->willReturn(self::NOW);

        $this->authentication = $this->createMock(AuthenticationInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        $this->recent = new RecentAuthentication(
            $session,
            $this->authentication,
            $config,
            $dateTime,
            $this->logger
        );
    }

    public function testNeverAuthenticatedIsStale(): void
    {
        self::assertFalse($this->recent->isFresh());
    }

    public function testMarkNowIsFresh(): void
    {
        $this->recent->markNow();

        self::assertSame(self::NOW, $this->store['dmlab_customer_passkey_auth_at']);
        self::assertTrue($this->recent->isFresh());
    }

    public function testFreshAtWindowEdge(): void
    {
        $this->store['dmlab_customer_passkey_auth_at'] = self::NOW - 300;

        self::assertTrue($this->recent->isFresh());
    }

    public function testStalePastWindow(): void
    {
        $this->store['dmlab_customer_passkey_auth_at'] = self::NOW - 301;

        self::assertFalse($this->recent->isFresh());
    }

    public function testImpersonationSessionIsNeverFresh(): void
    {
        $this->recent->markNow();
        $this->store['logged_as_customer_admind_id'] = 1;

        self::assertFalse($this->recent->isFresh());
    }

    public function testConfirmPasswordAcceptsCorrectPassword(): void
    {
        $this->authentication->expects(self::once())->method('authenticate')
            ->with(42, 'secret')
            ->willReturn(true);
        $this->logger->expects(self::never())->method('info');

        self::assertTrue($this->recent->confirmPassword(42, 'secret'));
    }

    public function testConfirmPasswordRejectsWrongPassword(): void
    {
        $this->authentication->method('authenticate')
            ->willThrowException(new InvalidEmailOrPasswordException(new Phrase('Invalid login or password.')));
        $this->logger->expects(self::once())->method('info');

        self::assertFalse($this->recent->confirmPassword(42, 'wrong'));
    }

    public function testConfirmPasswordRejectsLockedAccountWithCorrectPassword(): void
    {
        // Native authenticate() accepts a correct password even while locked.
        $this->authentication->method('isLocked')->with(42)->willReturn(true);
        $this->authentication->method('authenticate')->willReturn(true);
        $this->logger->expects(self::once())->method('info');

        self::assertFalse($this->recent->confirmPassword(42, 'secret'));
    }

    public function testConfirmPasswordRejectsAccountLockedByThisFailure(): void
    {
        $this->authentication->method('authenticate')
            ->willThrowException(new UserLockedException(new Phrase('Account locked.')));
        $this->logger->expects(self::once())->method('info');

        self::assertFalse($this->recent->confirmPassword(42, 'wrong'));
    }

    public function testConfirmPasswordRejectsDeletedCustomer(): void
    {
        $this->authentication->method('isLocked')
            ->willThrowException(new NoSuchEntityException(new Phrase('No such entity.')));
        $this->logger->expects(self::once())->method('info');

        self::assertFalse($this->recent->confirmPassword(42, 'secret'));
    }
}
