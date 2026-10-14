import sharp from 'sharp';
import { readFile, writeFile, mkdir } from 'node:fs/promises';

// 所有平台图标来自同一份矢量母版，托盘使用放大笔画的独立小尺寸图形。
const directory = 'assets/icons';
await mkdir(directory, { recursive: true });
await mkdir('artifacts', { recursive: true });
const logo = await readFile('assets/brand/logo.svg', 'utf8');
const glyph = await readFile('assets/brand/glyph.svg', 'utf8');
const paths = glyph.match(/<g[\s\S]*<\/g>/)[0];
const micro = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><rect x=".5" y=".5" width="23" height="23" rx="5" fill="#2861CE"/><g transform="translate(2 2) scale(.833333)">${paths.replace('#000000', '#FFFFFF')}</g></svg>`;
const desktop = new Map();
for (const size of [16, 24, 32, 48, 64, 128, 256, 512, 1024]) {
  const buffer = await sharp(Buffer.from(size < 48 ? micro : logo))
    .resize(size, size)
    .png()
    .toBuffer();
  desktop.set(size, buffer);
  await writeFile(`${directory}/${size}x${size}.png`, buffer);
}
// Windows Vista 及以后支持 ICO 内嵌 PNG；尺寸 256 在目录表中用 0 表示。
const frames = [16, 24, 32, 48, 64, 128, 256];
const header = Buffer.alloc(6 + frames.length * 16);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(frames.length, 4);
let offset = header.length;
frames.forEach((size, index) => {
  const row = 6 + index * 16;
  const data = desktop.get(size);
  header[row] = size === 256 ? 0 : size;
  header[row + 1] = header[row];
  header.writeUInt16LE(1, row + 4);
  header.writeUInt16LE(32, row + 6);
  header.writeUInt32LE(data.length, row + 8);
  header.writeUInt32LE(offset, row + 12);
  offset += data.length;
});
await writeFile(
  `${directory}/icon.ico`,
  Buffer.concat([header, ...frames.map((size) => desktop.get(size))]),
);
// 使用现代 PNG 类型构造 ICNS，在 Windows/Linux 上也能复现图标生成。
const entries = [
  ['icp4', 16],
  ['icp5', 32],
  ['icp6', 64],
  ['ic07', 128],
  ['ic08', 256],
  ['ic09', 512],
  ['ic10', 1024],
  ['ic11', 32],
  ['ic12', 64],
  ['ic13', 256],
  ['ic14', 512],
];
const chunks = entries.map(([type, size]) => {
  const data = desktop.get(size);
  const entry = Buffer.alloc(8);
  entry.write(type, 0, 'ascii');
  entry.writeUInt32BE(data.length + 8, 4);
  return Buffer.concat([entry, data]);
});
const icns = Buffer.alloc(8);
icns.write('icns', 0, 'ascii');
icns.writeUInt32BE(8 + chunks.reduce((sum, chunk) => sum + chunk.length, 0), 4);
await writeFile(`${directory}/icon.icns`, Buffer.concat([icns, ...chunks]));
for (const [name, svg, size] of [
  ['trayTemplate', glyph, 18],
  ['trayColor', micro, 20],
  ['trayDark', glyph.replace('#000000', '#FFFFFF'), 18],
]) {
  for (const scale of [1, 2])
    await sharp(Buffer.from(svg))
      .resize(size * scale, size * scale)
      .png()
      .toFile(`${directory}/${name}${scale === 2 ? '@2x' : ''}.png`);
}
const uri = (svg) => `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
const preview = `<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="760">
<rect width="1120" height="760" fill="#F2F5FA"/>
<g font-family="PingFang SC,Microsoft YaHei,sans-serif" fill="#25344E"><text x="48" y="65" font-size="30" font-weight="600">穿透工作台 · 图标系统</text><text x="48" y="100" font-size="16" fill="#7B879A">两端入口，一条隧道。桌面彩色识别，托盘单色适配。</text>
<rect x="40" y="135" width="500" height="365" rx="24" fill="#FFFFFF"/><rect x="560" y="135" width="520" height="365" rx="24" fill="#16243C"/>
<image href="${uri(logo)}" x="158" y="158" width="264" height="264"/><image href="${uri(logo)}" x="686" y="158" width="264" height="264"/>
<text x="290" y="465" text-anchor="middle" font-size="16">桌面图标 · 浅色背景</text><text x="820" y="465" text-anchor="middle" font-size="16" fill="#E1E9F7">桌面图标 · 深色背景</text>
<rect x="40" y="525" width="1040" height="185" rx="24" fill="#FFFFFF"/><text x="68" y="565" font-size="16">托盘与小尺寸图标</text>
<rect x="68" y="590" width="200" height="64" rx="12" fill="#F0F3F8"/><rect x="296" y="590" width="200" height="64" rx="12" fill="#16243C"/>
<image href="${uri(glyph)}" x="90" y="610" width="24" height="24"/><image href="${uri(glyph.replace('#000000', '#FFFFFF'))}" x="318" y="610" width="24" height="24"/>
<text x="130" y="627" font-size="13">macOS 模板</text><text x="356" y="627" font-size="13" fill="#E1E9F7">深色主题</text>
${[16, 24, 32, 48, 64].map((size, index) => `<image href="${uri(size < 48 ? micro : logo)}" x="${555 + index * 92}" y="${622 - size / 2}" width="${size}" height="${size}"/><text x="${555 + index * 92 + size / 2}" y="683" font-size="12" text-anchor="middle" fill="#7B879A">${size} px</text>`).join('')}
</g></svg>`;
await writeFile('artifacts/logo-preview.svg', preview);
await sharp(Buffer.from(preview)).png().toFile('artifacts/logo-preview.png');
console.log('桌面 PNG/ICO/ICNS、托盘 1x/2x 与图标预览已生成。');
