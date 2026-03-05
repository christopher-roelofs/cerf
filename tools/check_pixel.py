"""Check pixel color at a screen coordinate. Usage: check_pixel.py x y"""
import sys, ctypes

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

def get_pixel_color(x, y):
    hdc = user32.GetDC(0)
    color = gdi32.GetPixel(hdc, x, y)
    user32.ReleaseDC(0, hdc)
    r = color & 0xFF
    g = (color >> 8) & 0xFF
    b = (color >> 16) & 0xFF
    return r, g, b, color

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: check_pixel.py x y")
        sys.exit(1)
    x, y = int(sys.argv[1]), int(sys.argv[2])
    r, g, b, raw = get_pixel_color(x, y)
    print(f"Pixel ({x},{y}): RGB({r},{g},{b}) = #{r:02X}{g:02X}{b:02X} raw=0x{raw:06X}")
