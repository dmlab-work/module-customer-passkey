<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Test\Unit\Helper\InMemorySession;
use Magento\Framework\Stdlib\DateTime\DateTime;
use PHPUnit\Framework\TestCase;

class ChallengeStorageTest extends TestCase
{
    /** @var array<string,mixed> */
    private array $store = [];

    /** @var ChallengeStorage */
    private ChallengeStorage $storage;

    /** @var int fake clock read by the storage (unix seconds) */
    private int $now = 1_800_000_000;

    protected function setUp(): void
    {
        $this->store = [];

        $session = new InMemorySession($this->store);

        $config = $this->createStub(Config::class);
        $config->method('getTimeout')->willReturn(60000);
        $dateTime = $this->createStub(DateTime::class);
        $dateTime->method('gmtTimestamp')->willReturnCallback(fn(): int => $this->now);

        $this->storage = new ChallengeStorage($session, $config, $dateTime);
    }

    public function testChallengeIsAcceptedUntilTimeoutPlusGrace(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'bytes');
        $this->now += 60 + ChallengeStorage::EXPIRY_GRACE_SECONDS;

        self::assertSame(
            ['challenge' => 'bytes', 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_LOGIN)
        );
    }

    public function testExpiredChallengeIsRejectedAndCleared(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'bytes');
        $this->now += 60 + ChallengeStorage::EXPIRY_GRACE_SECONDS + 1;

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
        self::assertSame([], $this->store);
    }

    public function testSlotWithoutIssueTimeIsRejected(): void
    {
        $this->store['dmlab_customer_passkey_challenge'] = (string)json_encode([
            'c' => base64_encode('legacy'),
            's' => null,
            't' => ChallengeStorage::CEREMONY_LOGIN,
        ]);

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
    }

    public function testChallengeIsConsumedOnce(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, 'challenge-bytes');

        self::assertSame(
            ['challenge' => 'challenge-bytes', 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_REGISTER)
        );
        // Single-use: a replayed ceremony finds nothing.
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testLoginChallengeRoundTrips(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'login-bytes');

        self::assertSame(
            ['challenge' => 'login-bytes', 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_LOGIN)
        );
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
    }

    public function testConsumeWithoutSaveReturnsNull(): void
    {
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testLoginChallengeCannotCompleteRegistration(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'login-bytes', 42);

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
        // The mismatch burns the slot — the challenge cannot be retried for login either.
        self::assertSame([], $this->store);
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
    }

    public function testRegisterChallengeCannotCompleteLogin(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, 'register-bytes');

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
        self::assertSame([], $this->store);
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testSlotWithoutCeremonyIsRejected(): void
    {
        // Pre-upgrade session format: no ceremony type.
        $this->store['dmlab_customer_passkey_challenge'] = (string)json_encode([
            'c' => base64_encode('legacy'),
            's' => null,
        ]);

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
        self::assertSame([], $this->store);
    }

    public function testCorruptSlotIsRejectedAndCleared(): void
    {
        foreach (['not-json', (string)json_encode(['c' => 1, 't' => ChallengeStorage::CEREMONY_LOGIN])] as $slot) {
            $this->store['dmlab_customer_passkey_challenge'] = $slot;

            self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
            self::assertSame([], $this->store);
        }
    }

    public function testBinaryChallengeRoundTrips(): void
    {
        $raw = "\x00\x01\xff\xfe\x10challenge";
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, $raw);

        self::assertSame(
            ['challenge' => $raw, 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_REGISTER)
        );
    }

    public function testSaveReplacesPendingChallenge(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'first');
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, 'second');

        self::assertSame(
            ['challenge' => 'second', 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_REGISTER)
        );
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testLoginScopeIsBoundToTheChallenge(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'scoped', 42);

        self::assertSame(
            ['challenge' => 'scoped', 'scope' => 42],
            $this->storage->consume(ChallengeStorage::CEREMONY_LOGIN)
        );
    }

    public function testUnknownEmailScopeRoundTripsAsZero(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'scoped', 0);

        self::assertSame(
            ['challenge' => 'scoped', 'scope' => 0],
            $this->storage->consume(ChallengeStorage::CEREMONY_LOGIN)
        );
    }
}
