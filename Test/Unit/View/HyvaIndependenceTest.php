<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\View;

use PHPUnit\Framework\TestCase;

/**
 * The module installs without Hyvä: no Hyvä class references, no Hyvä package, no hardcoded theme codes.
 */
class HyvaIndependenceTest extends TestCase
{
    private const SCANNED = ['etc', 'Block', 'Controller', 'Model', 'Observer', 'view'];

    public function testNoHyvaClassReferencesOutsideTemplateDocblocks(): void
    {
        $offenders = [];
        foreach ($this->files() as $relative => $path) {
            $hyvaTemplate = (bool)preg_match('#(-hyva\.phtml|/hyva/[^/]+\.phtml)$#', $relative);
            foreach (file($path) ?: [] as $number => $line) {
                if (!preg_match('/\\\\?Hyva\\\\/', $line)) {
                    continue;
                }
                if ($hyvaTemplate && preg_match('#^\s*\*\s*@var\s+\\\\?Hyva\\\\#', $line)) {
                    continue;
                }
                $offenders[] = $relative . ':' . ($number + 1);
            }
        }

        self::assertSame([], $offenders);
    }

    public function testComposerRequiresNoHyvaPackage(): void
    {
        $composer = json_decode(
            (string)file_get_contents($this->root() . '/composer.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $packages = array_keys(($composer['require'] ?? []) + ($composer['require-dev'] ?? []));

        self::assertSame([], array_values(array_filter(
            $packages,
            static fn (string $name): bool => str_starts_with($name, 'hyva-themes/')
        )));
    }

    public function testLayoutsHardcodeNoThemeCode(): void
    {
        $layouts = glob($this->root() . '/view/frontend/layout/*.xml') ?: [];
        self::assertNotSame([], $layouts);

        foreach ($layouts as $layout) {
            self::assertStringNotContainsString('Hyva/', (string)file_get_contents($layout), basename($layout));
        }
    }

    /**
     * @return array<string, string> relative path => absolute path
     */
    private function files(): array
    {
        $files = [];
        foreach (self::SCANNED as $dir) {
            $base = $this->root() . '/' . $dir;
            if (!is_dir($base)) {
                continue;
            }
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if ($file instanceof \SplFileInfo && $file->isFile()) {
                    $files[substr($file->getPathname(), strlen($this->root()) + 1)] = $file->getPathname();
                }
            }
        }
        self::assertNotSame([], $files);

        return $files;
    }

    private function root(): string
    {
        return dirname(__DIR__, 3);
    }
}
