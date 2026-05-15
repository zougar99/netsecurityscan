"""Generate NetSecurityScan logo (PNG + ICO)"""
import sys
import os
from PIL import Image, ImageDraw, ImageFont, ImageFilter

SIZES = [16, 32, 48, 64, 128, 256]
COLOR_BG = (10, 20, 40)
COLOR_SHIELD = (0, 120, 212)
COLOR_SHIELD_INNER = (0, 90, 180)
COLOR_TEXT = (255, 255, 255)
COLOR_ACCENT = (0, 200, 255)

def create_logo(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size // 2
    r = size * 0.42

    # Shield shape
    shield = [
        (cx, int(cy - r * 1.1)),
        (int(cx + r * 1.0), int(cy - r * 0.2)),
        (int(cx + r * 0.9), int(cy + r * 0.5)),
        (cx, int(cy + r * 1.0)),
        (int(cx - r * 0.9), int(cy + r * 0.5)),
        (int(cx - r * 1.0), int(cy - r * 0.2)),
    ]
    draw.polygon(shield, fill=COLOR_SHIELD, outline=COLOR_ACCENT, width=max(1, size//64))

    # Inner shield
    inner = [
        (cx, int(cy - r * 0.7)),
        (int(cx + r * 0.6), int(cy - r * 0.1)),
        (int(cx + r * 0.55), int(cy + r * 0.3)),
        (cx, int(cy + r * 0.65)),
        (int(cx - r * 0.55), int(cy + r * 0.3)),
        (int(cx - r * 0.6), int(cy - r * 0.1)),
    ]
    draw.polygon(inner, fill=COLOR_SHIELD_INNER, outline=None)

    # SNS text
    try:
        font_size = int(size * 0.32)
        font = ImageFont.truetype("C:\\Windows\\Fonts\\segoeuib.ttf", font_size)
    except:
        try:
            font = ImageFont.truetype("C:\\Windows\\Fonts\\arialbd.ttf", font_size)
        except:
            font = ImageFont.load_default()

    text = "SNS"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = cx - tw // 2
    ty = cy - th // 2 - int(size * 0.02)
    draw.text((tx, ty), text, fill=COLOR_TEXT, font=font)

    # Small lock icon on shield
    lock_size = int(size * 0.12)
    lock_y = int(cy + r * 0.45)
    draw.rectangle([cx - lock_size//2, lock_y - lock_size//4,
                    cx + lock_size//2, lock_y + lock_size//4], fill=COLOR_ACCENT)
    draw.arc([cx - lock_size//2, lock_y - lock_size//2,
              cx + lock_size//2, lock_y + lock_size//4], 180, 360, fill=COLOR_ACCENT, width=max(1, size//64))

    # Glow effect for larger sizes
    if size >= 64:
        glow = img.filter(ImageFilter.GaussianBlur(radius=size//32))
        img = Image.alpha_composite(glow, img)

    return img

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))

    # Generate PNGs
    for s in SIZES:
        img = create_logo(s)
        img.save(os.path.join(out_dir, f'logo_{s}.png'))
        print(f'  logo_{s}.png')

    # Generate ICO (multi-size)
    icons = [create_logo(s) for s in SIZES]
    ico_path = os.path.join(out_dir, 'logo.ico')
    icons[0].save(ico_path, format='ICO', sizes=[(s, s) for s in SIZES],
                  append_images=icons[1:])
    print(f'  logo.ico ({len(SIZES)} sizes)')

    # Generate main logo (largest)
    main_img = create_logo(256)
    main_path = os.path.join(out_dir, 'logo.png')
    main_img.save(main_path)
    print(f'  logo.png (256x256)')

    print(f'\nLogo saved to: {out_dir}')

if __name__ == '__main__':
    main()
