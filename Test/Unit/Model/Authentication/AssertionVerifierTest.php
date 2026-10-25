<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Authentication;

use DmLab\CustomerPasskey\Model\Authentication\AssertionVerifier;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialLoader;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Client-caused rejections must surface as WebauthnException so the controller logs them below CRITICAL.
 */
class AssertionVerifierTest extends TestCase
{
    private const RAW_ID = 'raw-credential-id';
    private const CHALLENGE = 'challenge';
    private const RP_ID = 'acme.test';

    /** @var CredentialSourceRepository&Stub */
    private $sources;

    /** @var AssertionVerifier */
    private AssertionVerifier $verifier;

    protected function setUp(): void
    {
        $config = $this->createStub(Config::class);
        $config->method('getUserVerification')->willReturn('preferred');
        $config->method('getTimeout')->willReturn(60000);
        $rpFactory = $this->createStub(RelyingPartyEntityFactory::class);
        $rpFactory->method('create')->willReturn(PublicKeyCredentialRpEntity::create('Acme', self::RP_ID));
        $this->sources = $this->createStub(CredentialSourceRepository::class);

        $this->verifier = new AssertionVerifier($config, $rpFactory, $this->sources, new CredentialLoader());
    }

    public function testUnknownCredentialIsVerificationFailure(): void
    {
        $this->sources->method('findOneByCredentialId')->willReturn(null);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The credential is not registered.');

        $this->verifier->verify(self::CHALLENGE, $this->payload('signature'));
    }

    public function testCredentialOfAnotherAccountIsVerificationFailure(): void
    {
        $this->sources->method('findOneByCredentialId')->willReturn($this->source());

        $this->expectException(AuthenticatorResponseVerificationException::class);

        $this->verifier->verify(self::CHALLENGE, $this->payload('signature'), 7);
    }

    public function testMalformedSignatureIsVerificationFailure(): void
    {
        // The ECDSA decoder throws a plain InvalidArgumentException for a non-DER signature.
        $this->sources->method('findOneByCredentialId')->willReturn($this->source());

        try {
            $this->verifier->verify(self::CHALLENGE, $this->payload('not-a-der-signature'));
            self::fail('Expected a verification failure.');
        } catch (AuthenticatorResponseVerificationException $e) {
            self::assertInstanceOf(\InvalidArgumentException::class, $e->getPrevious());
        }
    }

    public function testWrongSignatureIsVerificationFailure(): void
    {
        $this->sources->method('findOneByCredentialId')->willReturn($this->source());

        $this->expectException(AuthenticatorResponseVerificationException::class);

        $this->verifier->verify(self::CHALLENGE, $this->payload("\x30\x06\x02\x01\x01\x02\x01\x01"));
    }

    /**
     * Stored credential with a real P-256 public key owned by customer 42.
     */
    private function source(): CredentialRecord
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $ec = openssl_pkey_get_details($key)['ec'];
        // COSE EC2 P-256 key map {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
        // OpenSSL drops leading zero bytes; COSE coordinates are fixed 32-byte strings.
        $x = str_pad($ec['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($ec['y'], 32, "\0", STR_PAD_LEFT);
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . $x . "\x22\x58\x20" . $y;

        return CredentialRecord::create(
            self::RAW_ID,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            $coseKey,
            '42',
            1
        );
    }

    /**
     * Browser assertion JSON that passes every ceremony step up to the signature check.
     *
     * @param string $signature raw signature bytes
     * @return array<string,mixed>
     */
    private function payload(string $signature): array
    {
        $clientData = (string)json_encode([
            'type' => 'webauthn.get',
            'challenge' => $this->base64Url(self::CHALLENGE),
            'origin' => 'https://' . self::RP_ID,
        ]);

        return [
            'id' => $this->base64Url(self::RAW_ID),
            'rawId' => $this->base64Url(self::RAW_ID),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($clientData),
                'authenticatorData' => $this->base64Url(hash('sha256', self::RP_ID, true) . "\x05" . pack('N', 7)),
                'signature' => $this->base64Url($signature),
                'userHandle' => $this->base64Url('42'),
            ],
        ];
    }

    /**
     * @param string $raw
     */
    private function base64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
