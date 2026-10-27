<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Framework\Stdlib\DateTime\DateTime;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;

#[AllowMockObjectsWithoutExpectations]
class CredentialSourceRepositoryTest extends TestCase
{
    private const AAGUID = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d';
    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';

    private const NOW = '2026-07-09 12:00:00';

    /** @var CredentialRepository&MockObject */
    private $credentials;

    /** @var CredentialSourceRepository */
    private CredentialSourceRepository $repository;

    protected function setUp(): void
    {
        $this->credentials = $this->createMock(CredentialRepository::class);
        $dateTime = $this->createStub(DateTime::class);
        $dateTime->method('gmtDate')->willReturn(self::NOW);
        $this->repository = new CredentialSourceRepository($this->credentials, $dateTime);
    }

    private function encodeBase64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public function testFindOneMapsStoredCredentialToSource(): void
    {
        $credential = new Credential(
            entityId: 3,
            customerId: 42,
            credentialId: $this->encodeBase64Url('raw-credential-id'),
            publicKey: base64_encode('raw-cose-key'),
            signCount: 5,
            transports: ['internal', 'hybrid'],
            aaguid: self::AAGUID,
            attestationType: 'packed'
        );
        $this->credentials->expects(self::once())->method('findByCredentialId')
            ->with($this->encodeBase64Url('raw-credential-id'))->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('raw-credential-id');

        self::assertInstanceOf(CredentialRecord::class, $source);
        self::assertSame('raw-credential-id', $source->publicKeyCredentialId);
        self::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $source->type);
        self::assertSame('raw-cose-key', $source->credentialPublicKey);
        self::assertSame(5, $source->counter);
        self::assertSame('42', $source->userHandle);
        self::assertSame(['internal', 'hybrid'], $source->transports);
        self::assertSame('packed', $source->attestationType);
        self::assertSame(self::AAGUID, $source->aaguid->toRfc4122());
    }

    public function testFindOneReturnsNullWhenAbsent(): void
    {
        $this->credentials->expects(self::once())->method('findByCredentialId')
            ->with($this->encodeBase64Url('missing'))->willReturn(null);

        self::assertNull($this->repository->findOneByCredentialId('missing'));
    }

    public function testFindOneMapsNullAaguidToNil(): void
    {
        $credential = new Credential(
            customerId: 1,
            credentialId: $this->encodeBase64Url('c'),
            publicKey: base64_encode('k'),
            aaguid: null
        );
        $this->credentials->method('findByCredentialId')->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('c');

        self::assertSame(self::NIL_AAGUID, $source->aaguid->toRfc4122());
    }

    public function testFindOneMapsStoredUserHandleAndFlags(): void
    {
        $credential = new Credential(
            customerId: 42,
            credentialId: $this->encodeBase64Url('c'),
            publicKey: base64_encode('k'),
            userHandle: $this->encodeBase64Url("opaque\x00handle"),
            backupEligible: true,
            backupStatus: false,
            uvInitialized: true
        );
        $this->credentials->method('findByCredentialId')->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('c');

        self::assertSame("opaque\x00handle", $source->userHandle);
        self::assertTrue($source->backupEligible);
        self::assertFalse($source->backupStatus);
        self::assertTrue($source->uvInitialized);
    }

    public function testFindOneMapsLegacyRowFlags(): void
    {
        $credential = new Credential(customerId: 42, credentialId: $this->encodeBase64Url('c'), publicKey: 'aw==');
        $this->credentials->method('findByCredentialId')->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('c');

        self::assertNull($source->backupEligible);
        self::assertNull($source->backupStatus);
        // Unknown counts as not yet verified, so the next UV assertion records it.
        self::assertFalse($source->uvInitialized);
    }

    public function testFindCustomerIdByCredentialId(): void
    {
        $this->credentials->method('findByCredentialId')->willReturnMap([
            [$this->encodeBase64Url('known'), new Credential(customerId: 42, credentialId: 'x')],
            [$this->encodeBase64Url('missing'), null],
        ]);

        self::assertSame(42, $this->repository->findCustomerIdByCredentialId('known'));
        self::assertNull($this->repository->findCustomerIdByCredentialId('missing'));
    }

    public function testFindAllForCustomerMapsEachCredential(): void
    {
        $credentials = [
            new Credential(customerId: 42, credentialId: $this->encodeBase64Url('a'), publicKey: base64_encode('ka')),
            new Credential(customerId: 42, credentialId: $this->encodeBase64Url('b'), publicKey: base64_encode('kb')),
        ];
        $this->credentials->expects(self::once())->method('listByCustomer')
            ->with(42)->willReturn($credentials);

        $sources = $this->repository->findAllForCustomer(42);

        self::assertCount(2, $sources);
        self::assertSame('a', $sources[0]->publicKeyCredentialId);
        self::assertSame('b', $sources[1]->publicKeyCredentialId);
    }

    public function testFindAllForInvalidCustomerReturnsEmpty(): void
    {
        $this->credentials->expects(self::never())->method('listByCustomer');

        self::assertSame([], $this->repository->findAllForCustomer(0));
    }

    public function testSaveCredentialSourceNeverRecreatesARemovedRow(): void
    {
        $source = $this->source('gone', 'key', userHandle: '77', counter: 1, aaguid: self::NIL_AAGUID);
        $this->credentials->method('findByCredentialId')->willReturn(null);

        $this->credentials->expects(self::never())->method('save');

        $this->repository->saveCredentialSource($source);
    }

    public function testSaveExistingCredentialPreservesOwnershipAndUpdatesCounter(): void
    {
        $existing = new Credential(
            entityId: 9,
            customerId: 42,
            credentialId: $this->encodeBase64Url('known'),
            publicKey: base64_encode('key'),
            signCount: 3,
            label: 'My laptop',
            createdAt: '2026-01-01 00:00:00'
        );
        $this->credentials->method('findByCredentialId')
            ->with($this->encodeBase64Url('known'))->willReturn($existing);

        $source = $this->source('known', 'key', userHandle: '999', counter: 10, aaguid: self::AAGUID);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $source->backupEligible = true;
        $source->backupStatus = true;
        $source->uvInitialized = true;
        $this->repository->saveCredentialSource($source);

        self::assertSame(9, $saved->entityId);
        self::assertTrue($saved->backupEligible);
        self::assertTrue($saved->backupStatus);
        self::assertTrue($saved->uvInitialized);
        self::assertNull($saved->userHandle, 'The registered handle is never rewritten on login.');
        // Ownership is not reassigned from the assertion's user handle.
        self::assertSame(42, $saved->customerId);
        self::assertSame('My laptop', $saved->label);
        self::assertSame('2026-01-01 00:00:00', $saved->createdAt);
        self::assertSame(10, $saved->signCount);
        self::assertSame(self::AAGUID, $saved->aaguid);
        self::assertSame(self::NOW, $saved->lastUsedAt, 'Login stamps the last-used time.');
    }

    public function testFindOneMapsInvalidStoredAaguidToNil(): void
    {
        $credential = new Credential(
            customerId: 1,
            credentialId: $this->encodeBase64Url('c'),
            publicKey: base64_encode('k'),
            aaguid: 'not-a-uuid'
        );
        $this->credentials->method('findByCredentialId')->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('c');

        self::assertSame(self::NIL_AAGUID, $source->aaguid->toRfc4122());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonRfc4122VariantAaguids(): array
    {
        return [
            'Chrome virtual authenticator' => ['01020304-0506-0708-0102-030405060708'],
            'Google Password Manager' => ['ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4'],
        ];
    }

    #[DataProvider('nonRfc4122VariantAaguids')]
    public function testNonRfc4122VariantAaguidSurvivesLoginRoundTrip(string $aaguid): void
    {
        $credential = new Credential(
            entityId: 5,
            customerId: 1,
            credentialId: $this->encodeBase64Url('c'),
            publicKey: base64_encode('k'),
            aaguid: $aaguid
        );
        $this->credentials->method('findByCredentialId')->willReturn($credential);
        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $source = $this->repository->findOneByCredentialId('c');
        self::assertSame($aaguid, $source->aaguid->toRfc4122());

        $this->repository->saveCredentialSource($source);
        self::assertSame($aaguid, $saved->aaguid);
    }

    public function testUppercaseStoredAaguidIsAccepted(): void
    {
        $credential = new Credential(
            customerId: 1,
            credentialId: $this->encodeBase64Url('c'),
            publicKey: base64_encode('k'),
            aaguid: strtoupper(self::AAGUID)
        );
        $this->credentials->method('findByCredentialId')->willReturn($credential);

        self::assertSame(self::AAGUID, $this->repository->findOneByCredentialId('c')->aaguid->toRfc4122());
    }

    public function testSaveNewCredentialAppliesLabelToNewRow(): void
    {
        $source = $this->source('fresh', 'fresh-key', userHandle: 'opaque', counter: 0, aaguid: self::AAGUID);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $this->repository->saveNewCredential($source, 55, 'Work key');

        self::assertNull($saved->entityId);
        self::assertSame(55, $saved->customerId);
        self::assertSame($this->encodeBase64Url('opaque'), $saved->userHandle);
        self::assertSame($this->encodeBase64Url('fresh'), $saved->credentialId);
        self::assertSame('Work key', $saved->label);
        self::assertSame(self::AAGUID, $saved->aaguid);
    }

    public function testSaveNewCredentialLeavesLabelNullWhenNotProvided(): void
    {
        $source = $this->source('fresh', 'fresh-key', userHandle: '55', counter: 0, aaguid: self::NIL_AAGUID);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $this->repository->saveNewCredential($source, 55, null);

        self::assertNull($saved->label);
    }

    private function source(
        string $rawId,
        string $rawKey,
        string $userHandle,
        int $counter,
        string $aaguid
    ): CredentialRecord {
        return CredentialRecord::create(
            $rawId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString($aaguid),
            $rawKey,
            $userHandle,
            $counter
        );
    }
}
