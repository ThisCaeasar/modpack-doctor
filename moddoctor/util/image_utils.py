"""Image utilities for mod icons."""

from PIL import Image, ImageDraw
from typing import Optional
import io


def create_placeholder_icon(size: tuple = (32, 32)) -> Image.Image:
    """Create a placeholder icon for mods without icons."""
    img = Image.new('RGBA', size, (128, 128, 128, 255))
    draw = ImageDraw.Draw(img)
    
    # Draw a simple mod icon placeholder
    margin = size[0] // 8
    inner_size = size[0] - 2 * margin
    
    # Draw a rounded rectangle
    draw.rounded_rectangle([margin, margin, margin + inner_size, margin + inner_size], 
                          radius=margin//2, fill=(64, 64, 64, 255))
    
    # Draw a simple "M" for mod
    font_size = inner_size // 3
    m_width = font_size // 2
    m_height = font_size
    
    start_x = margin + (inner_size - m_width) // 2
    start_y = margin + (inner_size - m_height) // 2
    
    # Simple M shape
    draw.rectangle([start_x, start_y, start_x + 2, start_y + m_height], fill=(255, 255, 255, 255))
    draw.rectangle([start_x + m_width - 2, start_y, start_x + m_width, start_y + m_height], fill=(255, 255, 255, 255))
    draw.rectangle([start_x + 2, start_y, start_x + m_width - 2, start_y + 2], fill=(255, 255, 255, 255))
    draw.rectangle([start_x + m_width//2 - 1, start_y + 2, start_x + m_width//2 + 1, start_y + m_height//2], fill=(255, 255, 255, 255))
    
    return img


def resize_icon(image: Image.Image, size: tuple = (32, 32)) -> Image.Image:
    """Resize an icon to the specified size, maintaining aspect ratio."""
    if image.size == size:
        return image
    
    # Calculate aspect ratio preserving size
    img_width, img_height = image.size
    target_width, target_height = size
    
    # Calculate scaling factor
    scale_w = target_width / img_width
    scale_h = target_height / img_height
    scale = min(scale_w, scale_h)
    
    # Calculate new size
    new_width = int(img_width * scale)
    new_height = int(img_height * scale)
    
    # Resize the image
    resized = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
    # If the image doesn't fill the target size, center it on a transparent background
    if (new_width, new_height) != size:
        centered = Image.new('RGBA', size, (0, 0, 0, 0))
        x_offset = (target_width - new_width) // 2
        y_offset = (target_height - new_height) // 2
        centered.paste(resized, (x_offset, y_offset))
        return centered
    
    return resized


def load_icon_from_bytes(data: bytes, size: tuple = (32, 32)) -> Optional[Image.Image]:
    """Load an icon from bytes data."""
    try:
        image = Image.open(io.BytesIO(data))
        # Convert to RGBA if needed
        if image.mode != 'RGBA':
            image = image.convert('RGBA')
        return resize_icon(image, size)
    except Exception:
        return None


def icon_to_bytes(image: Image.Image, format: str = 'PNG') -> bytes:
    """Convert an icon to bytes."""
    buffer = io.BytesIO()
    image.save(buffer, format=format)
    return buffer.getvalue()