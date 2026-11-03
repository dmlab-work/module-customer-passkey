<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\View;

use PHPUnit\Framework\TestCase;

/**
 * Hyvä templates are wired through `hyva_` handles only; the Luma layouts keep their blocks and templates.
 */
class HyvaLayoutTest extends TestCase
{
    private const MODULE = 'DmLab_CustomerPasskey::';

    public function testHyvaLoginLayoutRedeclaresButtonWithHyvaTemplateAndWebauthnChild(): void
    {
        $xpath = $this->layout('hyva_customer_account_login.xml');

        self::assertSame(1, $xpath->query('/page/body/*')->length);
        $refs = $xpath->query(
            '/page/body/referenceContainer[@name="customer.login.container"]'
            . '/block[@name="dmlab.customer.passkey.button"]'
        );
        self::assertSame(1, $refs->length);
        $ref = $refs->item(0);
        self::assertInstanceOf(\DOMElement::class, $ref);
        self::assertSame(\DmLab\CustomerPasskey\Block\Login\Passkey::class, $ref->getAttribute('class'));
        self::assertSame('customer_form_login', $ref->getAttribute('before'));
        self::assertSame(self::MODULE . 'login/passkey-button-hyva.phtml', $ref->getAttribute('template'));

        $children = $xpath->query('block[@as="webauthn"]', $ref);
        self::assertSame(1, $children->length);
        $child = $children->item(0);
        self::assertInstanceOf(\DOMElement::class, $child);
        self::assertSame('dmlab.customer.passkey.webauthn.hyva', $child->getAttribute('name'));
        self::assertSame(\Magento\Framework\View\Element\Template::class, $child->getAttribute('class'));
        self::assertSame(self::MODULE . 'hyva/webauthn.phtml', $child->getAttribute('template'));
    }

    public function testHyvaLoginTemplatesExist(): void
    {
        self::assertFileExists($this->template('login/passkey-button-hyva.phtml'));
        self::assertFileExists($this->template('hyva/webauthn.phtml'));
    }

    public function testLumaLoginLayoutKeepsButtonBlock(): void
    {
        $xpath = $this->layout('customer_account_login.xml');

        $blocks = $xpath->query(
            '/page/body/referenceContainer[@name="customer.login.container"]'
            . '/block[@name="dmlab.customer.passkey.button"]'
        );
        self::assertSame(1, $blocks->length);
        $block = $blocks->item(0);
        self::assertInstanceOf(\DOMElement::class, $block);
        self::assertSame(\DmLab\CustomerPasskey\Block\Login\Passkey::class, $block->getAttribute('class'));
        self::assertSame(self::MODULE . 'login/passkey-button.phtml', $block->getAttribute('template'));
        self::assertSame('customer_form_login', $block->getAttribute('before'));
    }

    public function testHyvaManageLayoutSwitchesListTemplateAndAddsWebauthnChild(): void
    {
        $xpath = $this->layout('hyva_customerpasskey_manage_index.xml');

        $refs = $xpath->query('/page/body/referenceBlock[@name="dmlab.customer.passkey.list"]');
        self::assertSame(1, $refs->length);
        $ref = $refs->item(0);
        self::assertInstanceOf(\DOMElement::class, $ref);
        self::assertSame(self::MODULE . 'manage/list-hyva.phtml', $ref->getAttribute('template'));

        $children = $xpath->query('block[@as="webauthn"]', $ref);
        self::assertSame(1, $children->length);
        $child = $children->item(0);
        self::assertInstanceOf(\DOMElement::class, $child);
        self::assertSame('dmlab.customer.passkey.manage.webauthn.hyva', $child->getAttribute('name'));
        self::assertSame(\Magento\Framework\View\Element\Template::class, $child->getAttribute('class'));
        self::assertSame(self::MODULE . 'hyva/webauthn.phtml', $child->getAttribute('template'));
    }

    public function testHyvaManageTemplateExists(): void
    {
        self::assertFileExists($this->template('manage/list-hyva.phtml'));
    }

    public function testLumaManageLayoutKeepsListBlock(): void
    {
        $xpath = $this->layout('customerpasskey_manage_index.xml');

        $blocks = $xpath->query(
            '/page/body/referenceContainer[@name="content"]/block[@name="dmlab.customer.passkey.list"]'
        );
        self::assertSame(1, $blocks->length);
        $block = $blocks->item(0);
        self::assertInstanceOf(\DOMElement::class, $block);
        self::assertSame(\DmLab\CustomerPasskey\Block\Manage\ListPasskeys::class, $block->getAttribute('class'));
        self::assertSame(self::MODULE . 'manage/list.phtml', $block->getAttribute('template'));
        self::assertSame('false', $block->getAttribute('cacheable'));
        self::assertSame(1, $xpath->query('/page/update[@handle="customer_account"]')->length);
    }

    private function layout(string $file): \DOMXPath
    {
        $path = dirname(__DIR__, 3) . '/view/frontend/layout/' . $file;
        self::assertFileExists($path);

        $dom = new \DOMDocument();
        self::assertTrue($dom->load($path), $file . ' is not well-formed XML');

        return new \DOMXPath($dom);
    }

    private function template(string $file): string
    {
        return dirname(__DIR__, 3) . '/view/frontend/templates/' . $file;
    }
}
