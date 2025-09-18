"""Image utilities for icon handling."""

import io
from pathlib import Path
from typing import Optional

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def create_placeholder_icon(size: tuple = (64, 64), text: str = "?") -> Optional[bytes]:
    """
    Create a placeholder icon with the given text.
    
    Args:
        size: Icon size as (width, height)
        text: Text to display on the icon
        
    Returns:
        PNG icon data as bytes, or None if PIL is not available
    """
    if not PIL_AVAILABLE:
        return None
    
    try:
        # Create image with light gray background
        img = Image.new('RGBA', size, (200, 200, 200, 255))
        draw = ImageDraw.Draw(img)
        
        # Try to load a font, fall back to default
        try:
            font_size = min(size) // 3
            font = ImageFont.truetype("arial.ttf", font_size)
        except Exception:
            try:
                font = ImageFont.load_default()
            except Exception:
                font = None
        
        # Draw text in center
        if font:
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
        else:
            # Estimate text size without font
            text_width = len(text) * 8
            text_height = 12
        
        x = (size[0] - text_width) // 2
        y = (size[1] - text_height) // 2
        
        if font:
            draw.text((x, y), text, fill=(80, 80, 80, 255), font=font)
        else:
            draw.text((x, y), text, fill=(80, 80, 80, 255))
        
        # Convert to PNG bytes
        output = io.BytesIO()
        img.save(output, format='PNG')
        return output.getvalue()
        
    except Exception:
        return None


def resize_image(image_data: bytes, size: tuple = (64, 64)) -> Optional[bytes]:
    """
    Resize an image to the specified size.
    
    Args:
        image_data: Original image data as bytes
        size: Target size as (width, height)
        
    Returns:
        Resized PNG image data as bytes, or None if failed
    """
    if not PIL_AVAILABLE:
        return None
    
    try:
        img = Image.open(io.BytesIO(image_data))
        
        # Convert to RGBA if needed
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        # Resize with high-quality resampling
        img = img.resize(size, Image.Resampling.LANCZOS)
        
        # Convert to PNG bytes
        output = io.BytesIO()
        img.save(output, format='PNG')
        return output.getvalue()
        
    except Exception:
        return None


def load_image_from_file(file_path: Path) -> Optional[bytes]:
    """
    Load image data from a file.
    
    Args:
        file_path: Path to the image file
        
    Returns:
        Image data as bytes, or None if failed
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception:
        return None


def create_mod_icon(mod_name: str, size: tuple = (64, 64)) -> Optional[bytes]:
    """
    Create an icon for a mod based on its name.
    
    Args:
        mod_name: Name of the mod
        size: Icon size as (width, height)
        
    Returns:
        PNG icon data as bytes
    """
    if not mod_name:
        return create_placeholder_icon(size, "?")
    
    # Use first letter of mod name
    first_letter = mod_name[0].upper()
    return create_placeholder_icon(size, first_letter)