<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Controller\Manage;

use DmLab\CustomerPasskey\Model\CredentialRepository;
use DmLab\CustomerPasskey\Model\Notification\PasskeyNotifier;
use DmLab\CustomerPasskey\Model\Security\RecentAuthentication;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Phrase;

/**
 * Deletes one of the signed-in customer's passkeys.
 *
 * The target is resolved only within the customer's own credential set
 * ({@see CredentialRepository::findOwnedByCustomer()}), so a forged `entity_id`
 * pointing at another shopper's passkey resolves to nothing and is refused — a
 * customer can only remove their own credentials. Guests get a 403 JSON error.
 * As for adding, outside the re-authentication window the current password
 * (`password` param) is required, else 401 with `reauth: true`.
 */
class Delete implements HttpPostActionInterface
{
    /**
     * @param Session $customerSession
     * @param RequestInterface $request
     * @param CredentialRepository $credentials
     * @param JsonFactory $resultJsonFactory
     * @param PasskeyNotifier $notifier
     * @param RecentAuthentication $recentAuthentication
     */
    public function __construct(
        private readonly Session $customerSession,
        private readonly RequestInterface $request,
        private readonly CredentialRepository $credentials,
        private readonly JsonFactory $resultJsonFactory,
        private readonly PasskeyNotifier $notifier,
        private readonly RecentAuthentication $recentAuthentication
    ) {
    }

    /**
     * Remove the passkey, or a JSON error (403 anonymous / 401 reauth / 404 not owned).
     *
     * @return Json
     */
    public function execute(): Json
    {
        $result = $this->resultJsonFactory->create();

        if (!$this->customerSession->isLoggedIn()) {
            return $this->error($result, 403, __('Please sign in to manage your passkeys.'));
        }

        $customerId = (int)$this->customerSession->getCustomerId();
        if (!$this->recentAuthentication->isFresh()) {
            $password = (string)$this->request->getParam('password', '');
            if ($password === '' || !$this->recentAuthentication->confirmPassword($customerId, $password)) {
                return $result->setHttpResponseCode(401)->setData([
                    'success' => false,
                    'reauth' => true,
                    'message' => $this->reauthMessage($password !== ''),
                ]);
            }
            $this->recentAuthentication->markNow();
        }

        $credential = $this->credentials->findOwnedByCustomer(
            $customerId,
            (int)$this->request->getParam('entity_id', 0)
        );
        if ($credential === null) {
            return $this->error($result, 404, __('Passkey not found.'));
        }

        $this->credentials->delete($credential);
        $this->notifier->notifyRemoved($this->customerSession->getCustomerData(), (string)$credential->label);

        return $result->setData(['success' => true, 'message' => __('Passkey removed.')]);
    }

    /**
     * The 401 prompt; customers without a password (SSO) are told to sign in again.
     *
     * @param bool $passwordGiven
     */
    private function reauthMessage(bool $passwordGiven): Phrase
    {
        return $passwordGiven
            ? __('The password is incorrect. No password (e.g. SSO)? Sign out and sign in again.')
            : __('Confirm your password to remove a passkey. No password (e.g. SSO)? Sign out and sign in again.');
    }

    /**
     * Emit a JSON error with the given HTTP status.
     *
     * @param Json $result
     * @param int $code
     * @param \Magento\Framework\Phrase $message
     */
    private function error(Json $result, int $code, \Magento\Framework\Phrase $message): Json
    {
        return $result->setHttpResponseCode($code)->setData([
            'success' => false,
            'message' => $message,
        ]);
    }
}
