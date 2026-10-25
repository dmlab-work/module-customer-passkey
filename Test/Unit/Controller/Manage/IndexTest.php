<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Controller\Manage;

use DmLab\CustomerPasskey\Controller\Manage\Index;
use Magento\Customer\Controller\AccountInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\App\ResponseInterface;
use Magento\Framework\View\Result\Page;
use Magento\Framework\View\Result\PageFactory;
use PHPUnit\Framework\TestCase;

class IndexTest extends TestCase
{
    public function testRendersPage(): void
    {
        $page = $this->createStub(Page::class);
        $pageFactory = $this->createMock(PageFactory::class);
        $pageFactory->expects(self::once())->method('create')->willReturn($page);
        $session = $this->createStub(Session::class);
        $session->method('authenticate')->willReturn(true);

        $controller = new Index($pageFactory, $session, $this->createStub(ResponseInterface::class));

        self::assertSame($page, $controller->execute());
    }

    public function testGuestGetsLoginRedirectResponse(): void
    {
        $pageFactory = $this->createMock(PageFactory::class);
        $pageFactory->expects(self::never())->method('create');
        $session = $this->createMock(Session::class);
        $session->expects(self::once())->method('authenticate')->willReturn(false);
        $response = $this->createStub(ResponseInterface::class);

        self::assertSame($response, (new Index($pageFactory, $session, $response))->execute());
    }

    public function testIsNotGatedByCoreAccountPlugin(): void
    {
        // Core's AccountInterface plugin returns null for guests, which breaks non-Action controllers.
        $controller = new Index(
            $this->createStub(PageFactory::class),
            $this->createStub(Session::class),
            $this->createStub(ResponseInterface::class)
        );

        self::assertNotInstanceOf(AccountInterface::class, $controller);
        self::assertInstanceOf(HttpGetActionInterface::class, $controller);
    }
}
