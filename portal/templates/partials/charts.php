<?php defined('PORTAL_ROOT') || exit;

/*
 * Server-rendered SVG charts (no script, no inline style: colours come from CSS classes).
 *   $charts = require PORTAL_ROOT . '/templates/partials/charts.php';
 *   echo $charts['bars']($days, $series, 'Logins');     stacked daily bars, wide + phone variants
 *   echo $charts['segments']($parts, 'Users by state'); one 100% bar with a legend
 * $series: list of ['key' => 'ok', 'label' => 'Accepted', 'class' => 'viz-s1'], bottom to top.
 */

$nice = static function (int $max): int {
    if ($max <= 4) {
        return 4;
    }
    $magnitude = 10 ** (int) floor(log10($max));
    foreach ([1, 2, 2.5, 5, 10] as $step) {
        if ($max <= $step * $magnitude) {
            return (int) ceil($step * $magnitude);
        }
    }
    return $max;
};

$svgBars = static function (array $days, array $series, string $title, int $width, string $variant) use ($nice): string {
    $height = 200;
    $left = 34;
    $right = 6;
    $top = 10;
    $bottom = 26;
    $plotW = $width - $left - $right;
    $plotH = $height - $top - $bottom;
    $n = max(1, count($days));
    $max = 0;
    foreach ($days as $day) {
        $sum = 0;
        foreach ($series as $s) {
            $sum += (int) $day[$s['key']];
        }
        $max = max($max, $sum);
    }
    $scaleMax = $nice($max);
    $slot = $plotW / $n;
    $barW = min($slot * 0.62, 26);
    $y = static fn (float $v): float => $top + $plotH - ($v / $scaleMax) * $plotH;
    $f = static fn (float $v): string => rtrim(rtrim(number_format($v, 2, '.', ''), '0'), '.');

    $svg = '<svg class="viz-svg viz-' . $variant . '" viewBox="0 0 ' . $width . ' ' . $height . '" role="img" aria-label="' . e($title) . '" focusable="false">';
    foreach ([0, 0.5, 1] as $fraction) {
        $value = $scaleMax * $fraction;
        $gy = $f($y($value));
        $svg .= '<line class="viz-grid' . (0 === $fraction ? ' viz-base' : '') . '" x1="' . $left . '" x2="' . ($width - $right) . '" y1="' . $gy . '" y2="' . $gy . '"/>';
        $svg .= '<text class="viz-tick" x="' . ($left - 8) . '" y="' . $f($y($value) + 4) . '" text-anchor="end">' . e($f($value)) . '</text>';
    }
    $every = (int) max(1, ceil($n / ('wide' === $variant ? 7 : 4)));
    foreach (array_values($days) as $i => $day) {
        $cx = $left + $slot * $i + $slot / 2;
        $x0 = $cx - $barW / 2;
        $parts = [];
        $base = 0.0;
        $tip = $day['label'] . ':';
        foreach ($series as $s) {
            $v = (int) $day[$s['key']];
            $tip .= ' ' . $v . ' ' . mb_strtolower($s['label']) . ',';
            if ($v > 0) {
                $parts[] = [$s['class'], $base, $base + $v];
                $base += $v;
            }
        }
        $svg .= '<g class="viz-col"><title>' . e(rtrim($tip, ',')) . '</title>';
        $svg .= '<rect class="viz-hit" x="' . $f($left + $slot * $i) . '" y="' . $top . '" width="' . $f($slot) . '" height="' . $plotH . '"/>';
        $last = count($parts) - 1;
        foreach ($parts as $k => [$class, $from, $to]) {
            $yTop = $y($to) + ($k > 0 ? 0 : 0);
            $yBottom = $y($from) - ($k > 0 ? 2 : 0); // 2px surface gap between stacked segments
            $h = max(0.0, $yBottom - $yTop);
            if ($h <= 0) {
                continue;
            }
            if ($k === $last) {
                $r = min(4.0, $h, $barW / 2);
                $d = 'M' . $f($x0) . ' ' . $f($yBottom) . 'V' . $f($yTop + $r) . 'Q' . $f($x0) . ' ' . $f($yTop) . ' ' . $f($x0 + $r) . ' ' . $f($yTop)
                    . 'H' . $f($x0 + $barW - $r) . 'Q' . $f($x0 + $barW) . ' ' . $f($yTop) . ' ' . $f($x0 + $barW) . ' ' . $f($yTop + $r) . 'V' . $f($yBottom) . 'Z';
                $svg .= '<path class="viz-bar ' . e($class) . '" d="' . $d . '"/>';
            } else {
                $svg .= '<rect class="viz-bar ' . e($class) . '" x="' . $f($x0) . '" y="' . $f($yTop) . '" width="' . $f($barW) . '" height="' . $f($h) . '"/>';
            }
        }
        if (0 === ($n - 1 - $i) % $every) {
            $svg .= '<text class="viz-tick" x="' . $f($cx) . '" y="' . ($height - 8) . '" text-anchor="middle">' . e($day['label']) . '</text>';
        }
        $svg .= '</g>';
    }
    return $svg . '</svg>';
};

return [
    'bars' => static function (array $days, array $series, string $title) use ($svgBars): string {
        $html = '<ul class="viz-legend">';
        foreach ($series as $s) {
            $total = array_sum(array_map(static fn (array $d): int => (int) $d[$s['key']], $days));
            $html .= '<li><span class="viz-swatch ' . e($s['class']) . '" aria-hidden="true"></span>' . e($s['label']) . ' <strong>' . (int) $total . '</strong></li>';
        }
        $html .= '</ul><div class="viz-frame">' . $svgBars($days, $series, $title, 640, 'wide') . $svgBars(array_slice($days, -7), $series, $title, 340, 'narrow') . '</div>';
        $html .= '<details class="viz-table"><summary>Show as a table</summary><div class="table-wrap"><table class="table"><thead><tr><th>Day (UTC)</th>';
        foreach ($series as $s) {
            $html .= '<th>' . e($s['label']) . '</th>';
        }
        $html .= '</tr></thead><tbody>';
        foreach (array_reverse($days) as $d) {
            $html .= '<tr><td>' . e($d['label']) . '</td>';
            foreach ($series as $s) {
                $html .= '<td>' . (int) $d[$s['key']] . '</td>';
            }
            $html .= '</tr>';
        }
        return $html . '</tbody></table></div></details>';
    },

    'segments' => static function (array $parts, string $title): string {
        $total = array_sum(array_column($parts, 'value'));
        $svg = '<svg class="viz-meter" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="' . e($title) . '" focusable="false">';
        $x = 0.0;
        $shown = array_values(array_filter($parts, static fn (array $p): bool => $p['value'] > 0));
        foreach ($shown as $i => $p) {
            $w = $total > 0 ? $p['value'] / $total * 100 : 0;
            $gap = $i < count($shown) - 1 ? 0.6 : 0;
            $svg .= '<rect class="' . e($p['class']) . '" x="' . round($x, 3) . '" y="0" width="' . round(max(0, $w - $gap), 3) . '" height="10"><title>' . e($p['label'] . ': ' . $p['value']) . '</title></rect>';
            $x += $w;
        }
        if (0 === $total) {
            $svg .= '<rect class="viz-empty" x="0" y="0" width="100" height="10"/>';
        }
        $svg .= '</svg><ul class="viz-legend viz-legend-stack">';
        foreach ($parts as $p) {
            $pct = $total > 0 ? round($p['value'] / $total * 100) : 0;
            $html = '<span class="viz-swatch ' . e($p['class']) . '" aria-hidden="true"></span><span class="viz-legend-label">' . e($p['label']) . '</span><strong>' . (int) $p['value'] . '</strong><span class="muted">' . $pct . '%</span>';
            $svg .= '<li>' . (isset($p['href']) ? '<a href="' . e($p['href']) . '">' . $html . '</a>' : $html) . '</li>';
        }
        return $svg . '</ul>';
    },
];
