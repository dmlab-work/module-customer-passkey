<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\View;

use DmLab\CustomerPasskey\Block\Login\Passkey;
use DmLab\CustomerPasskey\Block\Manage\ListPasskeys;
use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Test\Unit\Helper\HyvaCspSpy;
use Magento\Framework\Escaper;
use Magento\Framework\View\Element\Template;
use PHPUnit\Framework\TestCase;

/**
 * Renders the Hyvä templates with stub blocks and a `$hyvaCsp` spy.
 */
class HyvaTemplateRenderTest extends TestCase
{
    private const LOGIN_CONFIG = [
        'optionsUrl' => 'https://acme.test/customerpasskey/login/options',
        'verifyUrl' => 'https://acme.test/customerpasskey/login/verify',
        'formKey' => 'fk"<&>',
    ];

    private const MANAGE_CONFIG = [
        'optionsUrl' => 'https://acme.test/customerpasskey/register/options',
        'verifyUrl' => 'https://acme.test/customerpasskey/register/verify',
        'renameUrl' => 'https://acme.test/customerpasskey/manage/rename',
        'deleteUrl' => 'https://acme.test/customerpasskey/manage/delete',
        'formKey' => 'fk"<&>',
    ];

    public function testLoginButtonRendersConfigLabelsAndWebauthnChild(): void
    {
        $spy = new HyvaCspSpy();
        $html = $this->render('login/passkey-button-hyva.phtml', $this->loginBlock(true, $spy), $spy);

        self::assertSame(self::LOGIN_CONFIG, json_decode($this->attribute($html, 'data-config'), true));
        self::assertSame('Sign in with a passkey', $this->attribute($html, 'data-label-idle'));
        self::assertSame('Signing in…', $this->attribute($html, 'data-label-busy'));
        self::assertSame(
            'Passkeys are not supported on this browser.',
            $this->attribute($html, 'data-msg-unsupported')
        );
        self::assertSame(
            'Could not sign you in with a passkey. Please try again.',
            $this->attribute($html, 'data-msg-failure')
        );
        self::assertStringContainsString('x-data="dmlabCustomerPasskeyLogin"', $html);
        self::assertStringContainsString('col-span-full', $html);
        self::assertStringNotContainsString('fk"<&>', $html);

        $helpers = strpos($html, 'window.dmlabPasskeyWebauthn =');
        $component = strpos($html, 'function dmlabCustomerPasskeyLogin()');
        self::assertIsInt($helpers);
        self::assertIsInt($component);
        self::assertLessThan($component, $helpers);

        self::assertSame(2, substr_count($html, '<script>'));
        self::assertSame(2, $spy->calls);
    }

    public function testUnavailableLoginButtonRendersNothing(): void
    {
        $spy = new HyvaCspSpy();
        $html = $this->render('login/passkey-button-hyva.phtml', $this->loginBlock(false, $spy), $spy);

        self::assertSame('', trim($html));
        self::assertSame(0, $spy->calls);
    }

    public function testLoginButtonRendersWithoutHyvaCsp(): void
    {
        $html = $this->render('login/passkey-button-hyva.phtml', $this->loginBlock(true, null), null);

        self::assertSame(2, substr_count($html, '<script>'));
    }

    public function testManageListRendersRowsConfigAndWebauthnChild(): void
    {
        $spy = new HyvaCspSpy();
        $passkeys = [
            new Credential(entityId: 7, label: 'Work <laptop> "A"', createdAt: '2026-01-01 10:00:00'),
            new Credential(entityId: 12, label: 'Phone & key', createdAt: '2026-02-02 10:00:00'),
        ];
        $html = $this->render('manage/list-hyva.phtml', $this->manageBlock($passkeys, true, $spy), $spy);

        self::assertSame(self::MANAGE_CONFIG, json_decode($this->attribute($html, 'data-config'), true));
        self::assertStringNotContainsString('fk"<&>', $html);
        self::assertStringContainsString('x-data="dmlabCustomerPasskeyManage"', $html);

        self::assertSame(2, substr_count($html, '<tr>') - 1);
        self::assertSame(2, substr_count($html, 'data-entity-id="7"'));
        self::assertSame(2, substr_count($html, 'data-entity-id="12"'));
        self::assertStringContainsString('data-label="Work &lt;laptop&gt; &quot;A&quot;"', $html);
        self::assertStringContainsString('data-label="Phone &amp; key"', $html);
        self::assertStringContainsString('<td>Work &lt;laptop&gt; &quot;A&quot;</td>', $html);
        self::assertStringNotContainsString('<laptop>', $html);
        self::assertStringContainsString('<td>date:2026-01-01 10:00:00</td>', $html);
        self::assertStringContainsString('<td>date:</td>', $html);
        self::assertSame(2, substr_count($html, '@click="rename"'));
        self::assertSame(2, substr_count($html, '@click="remove"'));
        self::assertStringContainsString('@click="add"', $html);
        self::assertStringContainsString('x-ref="password"', $html);
        self::assertStringNotContainsString('You have no passkeys yet.', $html);

        $helpers = strpos($html, 'window.dmlabPasskeyWebauthn =');
        $component = strpos($html, 'function dmlabCustomerPasskeyManage()');
        self::assertIsInt($helpers);
        self::assertIsInt($component);
        self::assertLessThan($component, $helpers);

        self::assertSame(2, substr_count($html, '<script>'));
        self::assertSame(2, $spy->calls);
    }

    public function testManageListShowsEmptyState(): void
    {
        $spy = new HyvaCspSpy();
        $html = $this->render('manage/list-hyva.phtml', $this->manageBlock([], true, $spy), $spy);

        self::assertStringContainsString('You have no passkeys yet.', $html);
        self::assertStringNotContainsString('<table', $html);
        self::assertStringContainsString('@click="add"', $html);
        self::assertSame(2, $spy->calls);
    }

    public function testManageListHidesAddWhenDisabled(): void
    {
        $spy = new HyvaCspSpy();
        $passkeys = [new Credential(entityId: 3, label: 'Key')];
        $html = $this->render('manage/list-hyva.phtml', $this->manageBlock($passkeys, false, $spy), $spy);

        self::assertStringNotContainsString('@click="add"', $html);
        self::assertStringNotContainsString('Add a passkey', $html);
        self::assertStringContainsString('@click="remove"', $html);
    }

    public function testWebauthnPostPrefersHyvaFormKeyOverCachedOne(): void
    {
        $html = $this->render('hyva/webauthn.phtml', $this->createStub(Template::class), null);

        self::assertStringContainsString('window.hyva.getFormKey()', $html);
        self::assertStringContainsString('form_key: currentFormKey(formKey)', $html);
    }

    public function testManageListRendersWithoutHyvaCsp(): void
    {
        $html = $this->render('manage/list-hyva.phtml', $this->manageBlock([], true, null), null);

        self::assertSame(2, substr_count($html, '<script>'));
    }

    /**
     * @param Credential[] $passkeys
     */
    private function manageBlock(array $passkeys, bool $enabled, ?HyvaCspSpy $spy): ListPasskeys
    {
        $block = $this->createStub(ListPasskeys::class);
        $block->method('isEnabled')->willReturn($enabled);
        $block->method('getPasskeys')->willReturn($passkeys);
        $block->method('hasPasskeys')->willReturn($passkeys !== []);
        $block->method('getLabel')->willReturnCallback(static fn (Credential $c): string => (string)$c->label);
        $block->method('renderDate')->willReturnCallback(static fn (?string $v): string => 'date:' . $v);
        $block->method('getJsonConfig')->willReturn(json_encode(self::MANAGE_CONFIG, JSON_UNESCAPED_SLASHES));
        $block->method('getChildHtml')->willReturnCallback(
            fn (string $alias): string => $alias === 'webauthn'
                ? $this->render('hyva/webauthn.phtml', $this->createStub(Template::class), $spy)
                : ''
        );

        return $block;
    }

    private function loginBlock(bool $available, ?HyvaCspSpy $spy): Passkey
    {
        $block = $this->createStub(Passkey::class);
        $block->method('isAvailable')->willReturn($available);
        $block->method('getButtonLabel')->willReturn('Sign in with a passkey');
        $block->method('getJsonConfig')->willReturn(json_encode(self::LOGIN_CONFIG, JSON_UNESCAPED_SLASHES));
        $block->method('getChildHtml')->willReturnCallback(
            fn (string $alias): string => $alias === 'webauthn'
                ? $this->render('hyva/webauthn.phtml', $this->createStub(Template::class), $spy)
                : ''
        );

        return $block;
    }

    private function render(string $template, Template $block, ?HyvaCspSpy $spy): string
    {
        $escaper = $this->createStub(Escaper::class);
        $escaper->method('escapeHtmlAttr')->willReturnCallback(
            static fn ($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        );
        $escaper->method('escapeHtml')->willReturnCallback(
            static fn ($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        );

        $file = dirname(__DIR__, 3) . '/view/frontend/templates/' . $template;
        $include = static function (string $file, Template $block, Escaper $escaper, ?HyvaCspSpy $spy): string {
            if ($spy !== null) {
                $hyvaCsp = $spy;
            }
            ob_start();
            // phpcs:ignore Magento2.Security.IncludeFile
            include $file;

            return (string)ob_get_clean();
        };

        return $include($file, $block, $escaper, $spy);
    }

    private function attribute(string $html, string $name): string
    {
        self::assertSame(1, preg_match('/\s' . preg_quote($name, '/') . '="([^"]*)"/', $html, $match), $name);

        return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
