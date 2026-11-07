<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** QR codes as SVG data URIs, drawn by the barcode generator bundled with multiOTP (no GD needed). */
final class Qr
{
    public static function dataUri(string $text): ?string
    {
        try {
            MultiotpService::get(); // loads the bundled barcode generator
            if (!class_exists('barcode_generator', false)) {
                return null;
            }
            $svg = (new \barcode_generator())->render_svg('qr-m', $text, ['sf' => 6, 'p' => 4]);
            return is_string($svg) && '' !== $svg ? 'data:image/svg+xml;base64,' . base64_encode($svg) : null;
        } catch (\Throwable $error) {
            error_log('multiOTP portal QR code: ' . $error);
            return null;
        }
    }
}
