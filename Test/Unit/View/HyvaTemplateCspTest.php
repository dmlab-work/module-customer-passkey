<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\View;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every Hyvä template is compatible with the Alpine CSP build and Hyvä's strict CSP.
 */
class HyvaTemplateCspTest extends TestCase
{
    private const IDENTIFIER = '/^[A-Za-z_$][A-Za-z0-9_$.]*$/';

    /**
     * @return array<string,array{string}>
     */
    public static function templates(): array
    {
        $root = dirname(__DIR__, 3) . '/view/frontend/templates/';
        $files = array_merge(glob($root . 'hyva/*.phtml') ?: [], glob($root . '*/*-hyva.phtml') ?: []);
        $cases = [];
        foreach ($files as $file) {
            $cases[substr($file, strlen($root))] = [$file];
        }

        return $cases;
    }

    public function testCoversLoginTemplates(): void
    {
        self::assertArrayHasKey('login/passkey-button-hyva.phtml', self::templates());
        self::assertArrayHasKey('hyva/webauthn.phtml', self::templates());
    }

    public function testCoversManageTemplate(): void
    {
        self::assertArrayHasKey('manage/list-hyva.phtml', self::templates());
    }

    #[DataProvider('templates')]
    public function testNoInlineEventHandlersOrMageInit(string $file): void
    {
        $markup = $this->markup($file);

        self::assertDoesNotMatchRegularExpression('/\son[a-z]+\s*=/i', $markup);
        self::assertStringNotContainsString('data-mage-init', $markup);
        self::assertStringNotContainsString('x-model', $markup);
        self::assertDoesNotMatchRegularExpression('/\sstyle\s*=/i', $markup);
    }

    #[DataProvider('templates')]
    public function testNoRequireJsOrJquery(string $file): void
    {
        $source = (string)file_get_contents($file);

        foreach (['define(', 'require(', 'jQuery', '$.ajax', 'data-mage-init'] as $needle) {
            self::assertStringNotContainsString($needle, $source, $needle);
        }
    }

    #[DataProvider('templates')]
    public function testAlpineDirectivesArePlainIdentifiers(string $file): void
    {
        preg_match_all(
            '/\s(x-[a-z]+(?::[\w-]+)?(?:\.[\w-]+)*|:[a-z][\w-]*|@[a-z][\w:-]*(?:\.[\w-]+)*)'
            . '\s*=\s*(?:"([^"]*)"|\'([^\']*)\')/i',
            $this->markup($file),
            $matches,
            PREG_SET_ORDER
        );

        $offenders = [];
        foreach ($matches as $match) {
            [$directive, $value] = [$match[1], $match[3] ?? $match[2]];
            if (!preg_match(self::IDENTIFIER, $value)) {
                $offenders[] = $directive . '="' . $value . '"';
            }
        }

        self::assertSame([], $offenders);
    }

    #[DataProvider('templates')]
    public function testEveryComponentIsRegisteredOnAlpineInit(string $file): void
    {
        $source = (string)file_get_contents($file);
        preg_match_all('/\sx-data\s*=\s*"([^"]*)"/', $source, $matches);

        $unregistered = array_values(array_filter(
            $matches[1],
            static fn (string $name): bool => !preg_match(
                '/addEventListener\(\s*\'alpine:init\'[^;]*Alpine\.data\(\s*\'' . preg_quote($name, '/') . '\'/',
                $source
            )
        ));

        self::assertSame([], $unregistered);
    }

    #[DataProvider('templates')]
    public function testEveryInlineScriptIsRegistered(string $file): void
    {
        $source = (string)file_get_contents($file);
        $scripts = substr_count($source, '</script>');
        $registered = preg_match_all(
            '/<\/script>\s*<\?php\s+if\s*\(isset\(\$hyvaCsp\)\)\s*'
            . '\{\s*\$hyvaCsp->registerInlineScript\(\);\s*\}\s*\?>/',
            $source
        );

        self::assertGreaterThan(0, $scripts);
        self::assertSame($scripts, $registered);
    }

    /**
     * Template HTML without PHP blocks and `<script>` bodies, so only markup attributes are inspected.
     */
    private function markup(string $file): string
    {
        $source = (string)file_get_contents($file);
        $source = (string)preg_replace('/<\?(php|=).*?\?>/s', '', $source);

        return (string)preg_replace('/<script\b[^>]*>.*?<\/script>/s', '', $source);
    }
}
