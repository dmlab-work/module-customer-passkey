<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Registration;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Registration\AttestationVerifier;
use DmLab\CustomerPasskey\Model\Webauthn\CeremonyFactory;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialLoader;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use DmLab\CustomerPasskey\Model\Webauthn\UserHandle;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialRpEntity;

/**
 * Real registration ceremonies over software-built attestations (ES256 / Ed25519 keys).
 */
class AttestationVerifierTest extends TestCase
{
    private const RP_ID = 'acme.test';
    private const RAW_ID = 'raw-credential-id';
    private const CHALLENGE = 'registration-challenge';
    private const HANDLE = 'opaque-user-handle';

    /** Authenticator-data flags: user present, user verified, attested credential data. */
    private const FLAGS_UP_UV_AT = 0x45;

    /** @var AttestationVerifier */
    private AttestationVerifier $verifier;

    protected function setUp(): void
    {
        $config = $this->createStub(Config::class);
        $config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_REQUIRED);
        $config->method('getAllowedOrigins')->willReturn(['https://' . self::RP_ID]);
        $rpFactory = $this->createStub(RelyingPartyEntityFactory::class);
        $rpFactory->method('create')->willReturn(PublicKeyCredentialRpEntity::create('', self::RP_ID));
        $userHandle = $this->createStub(UserHandle::class);
        $userHandle->method('forCustomer')->willReturn(self::HANDLE);
        $ceremonyFactory = new CeremonyFactory($config);

        $this->verifier = new AttestationVerifier(
            $rpFactory,
            $config,
            new CredentialLoader($ceremonyFactory),
            $ceremonyFactory,
            $userHandle
        );
    }

    public function testAcceptsNoneAttestationAndIssuesOpaqueHandle(): void
    {
        [$coseKey] = $this->es256Key();

        $record = $this->verify($this->payload($coseKey));

        self::assertSame(self::RAW_ID, $record->publicKeyCredentialId);
        self::assertSame(self::HANDLE, $record->userHandle);
        self::assertSame(['internal', 'hybrid'], $record->transports);
        self::assertTrue($record->uvInitialized);
        self::assertFalse($record->backupEligible);
    }

    public function testAcceptsPackedSelfAttestation(): void
    {
        [$coseKey, $privateKey] = $this->es256Key();
        $authData = $this->authData($coseKey);
        $clientData = $this->clientData('webauthn.create');
        openssl_sign($authData . hash('sha256', $clientData, true), $signature, $privateKey, OPENSSL_ALGO_SHA256);
        // attStmt {"alg": -7, "sig": bytes}, no x5c: self attestation.
        $attStmt = "\xa2\x63alg\x26\x63sig\x58" . chr(strlen($signature)) . $signature;

        $record = $this->verify($this->payload($coseKey, $clientData, 'packed', $attStmt));

        self::assertSame('self', $record->attestationType);
    }

    public function testAcceptsEd25519Credential(): void
    {
        $keyPair = sodium_crypto_sign_keypair();
        // COSE OKP key map {1: 1, 3: -8, -1: 6, -2: x}.
        $coseKey = "\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20" . sodium_crypto_sign_publickey($keyPair);

        $record = $this->verify($this->payload($coseKey));

        self::assertSame($coseKey, $record->credentialPublicKey);
    }

    public function testRejectsAssertionClientDataType(): void
    {
        [$coseKey] = $this->es256Key();

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('webauthn.create');

        $this->verify($this->payload($coseKey, $this->clientData('webauthn.get')));
    }

    public function testRejectsSubdomainOrigin(): void
    {
        [$coseKey] = $this->es256Key();

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Subdomains are not allowed');

        $this->verify($this->payload($coseKey, $this->clientData('webauthn.create', 'https://evil.' . self::RP_ID)));
    }

    public function testRejectsMissingUserVerificationWhenRequired(): void
    {
        [$coseKey] = $this->es256Key();

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('User authentication required.');

        $this->verify($this->payload($coseKey, null, 'none', "\xa0", 0x41));
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function verify(array $payload): \Webauthn\CredentialRecord
    {
        return $this->verifier->verify(42, 'shopper@acme.test', 'Jane Shopper', self::CHALLENGE, $payload);
    }

    /**
     * A fresh P-256 key as [COSE key bytes, OpenSSL private key].
     *
     * @return array{string, \OpenSSLAsymmetricKey}
     */
    private function es256Key(): array
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $ec = openssl_pkey_get_details($key)['ec'];
        $x = str_pad($ec['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($ec['y'], 32, "\0", STR_PAD_LEFT);

        // COSE EC2 P-256 key map {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
        return ["\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . $x . "\x22\x58\x20" . $y, $key];
    }

    /**
     * @param string $coseKey
     * @param int $flags
     */
    private function authData(string $coseKey, int $flags = self::FLAGS_UP_UV_AT): string
    {
        return hash('sha256', self::RP_ID, true) . chr($flags) . pack('N', 0)
            . str_repeat("\0", 16) . pack('n', strlen(self::RAW_ID)) . self::RAW_ID . $coseKey;
    }

    /**
     * @param string $type
     * @param string|null $origin
     */
    private function clientData(string $type, ?string $origin = null): string
    {
        return (string)json_encode([
            'type' => $type,
            'challenge' => $this->base64Url(self::CHALLENGE),
            'origin' => $origin ?? 'https://' . self::RP_ID,
        ]);
    }

    /**
     * Browser attestation JSON as passkey-manage.js posts it.
     *
     * @param string $coseKey
     * @param string|null $clientData
     * @param string $fmt
     * @param string $attStmt CBOR-encoded attestation statement map
     * @param int $flags
     * @return array<string,mixed>
     */
    private function payload(
        string $coseKey,
        ?string $clientData = null,
        string $fmt = 'none',
        string $attStmt = "\xa0",
        int $flags = self::FLAGS_UP_UV_AT
    ): array {
        $authData = $this->authData($coseKey, $flags);
        // CBOR map {"fmt": text, "attStmt": map, "authData": bytes}; every item here is < 256 bytes.
        $attestationObject = "\xa3\x63fmt" . chr(0x60 + strlen($fmt)) . $fmt
            . "\x67attStmt" . $attStmt
            . "\x68authData\x58" . chr(strlen($authData)) . $authData;

        return [
            'id' => $this->base64Url(self::RAW_ID),
            'rawId' => $this->base64Url(self::RAW_ID),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($clientData ?? $this->clientData('webauthn.create')),
                'attestationObject' => $this->base64Url($attestationObject),
                'transports' => ['internal', 'hybrid'],
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
