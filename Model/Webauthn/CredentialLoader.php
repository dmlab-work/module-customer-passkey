<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Exception\WebauthnException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * Turns the browser credential JSON (decoded to an array) into the library's
 * {@see PublicKeyCredential} via the library serializer.
 *
 * Attestation formats are those the registration ceremony accepts
 * ({@see CeremonyFactory::attestationStatementSupportManager}). The
 * top-level shape is checked first: the library denormalizer neither rejects a
 * missing member nor a non-`public-key` type. Every failure surfaces as
 * {@see InvalidDataException}: the payload is client input, so callers can treat
 * it as a rejected request rather than a server fault.
 */
class CredentialLoader
{
    /**
     * @param CeremonyFactory $ceremonyFactory
     */
    public function __construct(
        private readonly CeremonyFactory $ceremonyFactory
    ) {
    }

    /**
     * Load the credential, throwing on any malformed input.
     *
     * @param array<string,mixed> $credential
     * @throws InvalidDataException when the payload is not a valid public-key credential
     */
    public function load(array $credential): PublicKeyCredential
    {
        foreach (['id', 'rawId', 'type'] as $key) {
            if (!isset($credential[$key]) || !is_string($credential[$key])) {
                throw InvalidDataException::create($credential, sprintf('The parameter "%s" is invalid.', $key));
            }
        }
        if ($credential['type'] !== PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY) {
            throw InvalidDataException::create($credential, 'Unsupported credential type.');
        }
        if (!isset($credential['response']) || !is_array($credential['response'])) {
            throw InvalidDataException::create($credential, 'The parameter "response" is invalid.');
        }

        try {
            $loaded = (new WebauthnSerializerFactory($this->ceremonyFactory->attestationStatementSupportManager()))
                ->create()
                ->deserialize(json_encode($credential, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
        } catch (WebauthnException $e) {
            throw $e;
        } catch (\Throwable $e) {
            // Decoders below the serializer throw generic Range/Json/InvalidArgument exceptions on garbage.
            throw InvalidDataException::create($credential, 'The credential could not be loaded.', $e);
        }
        if (!$loaded instanceof PublicKeyCredential) {
            throw InvalidDataException::create($credential, 'The credential could not be loaded.');
        }

        return $loaded;
    }
}
