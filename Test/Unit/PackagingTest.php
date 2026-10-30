<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit;

use PHPUnit\Framework\TestCase;

/**
 * composer.json declares the supported Magento/PHP range and the Packagist metadata; CI covers that range.
 */
class PackagingTest extends TestCase
{
    private const REPO = 'https://github.com/dmlab-work/module-customer-passkey';

    public function testComposerRequireSet(): void
    {
        self::assertSame(
            [
                'php' => '~8.2.0||~8.3.0||~8.4.0||~8.5.0',
                'ext-sodium' => '*',
                'magento/framework' => '^103.0.7',
                'magento/module-backend' => '^102.0.7',
                'magento/module-config' => '^101.2.7',
                'magento/module-customer' => '^103.0.7',
                'magento/module-email' => '^101.1.7',
                'magento/module-store' => '^101.1.7',
                'magento/module-ui' => '^101.2.7',
                'psr/log' => '^1.0|^2.0|^3.0',
                'symfony/serializer' => '^6.4|^7.0|^8.0',
                'symfony/uid' => '^6.4|^7.0|^8.0',
                'web-auth/cose-lib' => '^4.8',
                'web-auth/webauthn-lib' => '^5.3.5',
            ],
            $this->composer()['require'] ?? null
        );
    }

    public function testComposerRequireDevAllowsPhpunit11And12(): void
    {
        self::assertSame('^11.5||^12.5', $this->composer()['require-dev']['phpunit/phpunit'] ?? null);
    }

    public function testComposerKeywords(): void
    {
        $keywords = $this->composer()['keywords'] ?? [];
        $required = ['magento2', 'magento2-module', 'magento 2', 'passkey', 'webauthn', 'fido2', 'passwordless'];

        foreach ($required as $term) {
            self::assertContains($term, $keywords);
        }
    }

    public function testComposerHomepageAndSupport(): void
    {
        $composer = $this->composer();

        self::assertSame(self::REPO, $composer['homepage'] ?? null);
        self::assertSame(self::REPO . '/issues', $composer['support']['issues'] ?? null);
        self::assertSame(self::REPO, $composer['support']['source'] ?? null);
        self::assertArrayNotHasKey('suggest', $composer);
    }

    public function testVersionHasChangelogSection(): void
    {
        $version = $this->composer()['version'] ?? null;
        $changelog = (string)file_get_contents($this->moduleRoot() . '/CHANGELOG.md');

        self::assertSame('0.2.3', $version);
        self::assertMatchesRegularExpression(
            '/^## \\[' . preg_quote($version, '/') . '\\] — \\d{4}-\\d{2}-\\d{2}$/m',
            $changelog
        );
    }

    public function testCiTestsPhp82To85WithCoverageOn84(): void
    {
        $test = $this->ciJobs()['test'] ?? '';

        self::assertStringContainsString("php: ['8.2', '8.3', '8.4', '8.5']", $test);
        self::assertStringContainsString("matrix.php == '8.4' && '--coverage-clover coverage.xml'", $test);
    }

    public function testCiInstallsDoNotNotifyPackagist(): void
    {
        $test = $this->ciJobs()['test'] ?? '';
        $notify = 'composer config notify-on-install false';

        $this->assertPrecedes('name: Configure Magento packages', $notify, $test);
        $this->assertPrecedes($notify, 'ramsey/composer-install', $test);
    }

    public function testReadmeStatesRequirementsAndHyvaStatus(): void
    {
        $readme = $this->readme();

        self::assertStringContainsString("## Requirements\n\n- Magento 2.4.7+ · PHP 8.2–8.5\n", $readme);
        self::assertMatchesRegularExpression('/^## Hyvä$/m', $readme);
        self::assertStringContainsString(
            '<referenceBlock name="dmlab.customer.passkey.button"'
            . ' template="DmLab_CustomerPasskey::login/passkey-button-hyva.phtml"/>',
            $readme
        );
        self::assertFileExists($this->moduleRoot() . '/view/frontend/templates/login/passkey-button-hyva.phtml');
        self::assertStringContainsString(
            'name="dmlab.customer.passkey.button"',
            (string)file_get_contents($this->moduleRoot() . '/view/frontend/layout/customer_account_login.xml')
        );
    }

    public function testReadmeScreenshotExists(): void
    {
        $screenshot = '.github/images/login-passkey-button.png';

        self::assertStringContainsString('](' . $screenshot . ')', $this->readme());
        self::assertFileExists($this->moduleRoot() . '/' . $screenshot);
    }

    private function readme(): string
    {
        return (string)file_get_contents($this->moduleRoot() . '/README.md');
    }

    private function assertPrecedes(string $first, string $then, string $haystack): void
    {
        $firstAt = strpos($haystack, $first);
        $thenAt = strpos($haystack, $then);
        self::assertNotFalse($firstAt, $first);
        self::assertNotFalse($thenAt, $then);
        self::assertLessThan($thenAt, $firstAt, "'$first' must come before '$then'");
    }

    /**
     * Body of every top-level job in `ci.yml`, keyed by job id.
     *
     * @return array<string, string>
     */
    private function ciJobs(): array
    {
        $yaml = (string)file_get_contents($this->moduleRoot() . '/.github/workflows/ci.yml');
        $jobs = substr($yaml, (int)strpos($yaml, "\njobs:\n"));
        $parts = preg_split('/^  ([\w-]+):\n/m', $jobs, -1, PREG_SPLIT_DELIM_CAPTURE);
        self::assertIsArray($parts);
        $result = [];
        $count = count($parts);
        for ($i = 1; $i + 1 < $count; $i += 2) {
            $result[$parts[$i]] = $parts[$i + 1];
        }

        return $result;
    }

    /**
     * @return array<string, mixed>
     */
    private function composer(): array
    {
        $composer = json_decode((string)file_get_contents($this->moduleRoot() . '/composer.json'), true);
        self::assertIsArray($composer);

        return $composer;
    }

    private function moduleRoot(): string
    {
        return dirname(__DIR__, 2);
    }
}
