import io
import logging

log = logging.getLogger("exorcist.ocr")

# tesseract crawls on huge bitmaps, so bound the work two ways: never feed it more than this
# many pixels (kept low on purpose, OCR is single threaded and slow on small VPS cpus, and a
# capped image still reads scam text fine), and kill any read that still runs past the timeout.
# raise MAX_PIXELS if you run on a fast box and want a touch more accuracy on dense screenshots.
MAX_PIXELS = 2_000_000
READ_TIMEOUT = 20


class TesseractOCR:
    def __init__(self, cmd=None):
        import pytesseract
        from PIL import Image, ImageOps

        self._pt = pytesseract
        self._Image = Image
        self._ImageOps = ImageOps
        if cmd:
            pytesseract.pytesseract.tesseract_cmd = cmd

    def read(self, data):
        img = self._prep(self._Image.open(io.BytesIO(data)))
        # psm 6 reads the image as blocks of lines, which keeps phrases like
        # "your withdrawal of $2700" together instead of scattering the words
        return self._pt.image_to_string(img, config="--psm 6", timeout=READ_TIMEOUT)

    def _prep(self, img):
        # clean the image up before tesseract sees it: grayscale, flip dark mode
        # screenshots so the text is dark on light, scale to a readable size, stretch contrast
        ops = self._ImageOps
        img = img.convert("L")
        if self._mean(img) < 110:
            # most of these scams are dark mode posts, light text on black, which tesseract
            # reads terribly. inverting turns it into dark text on light, which it reads well
            img = ops.invert(img)
        img = self._fit(img)
        return ops.autocontrast(img, cutoff=2)

    def _fit(self, img):
        # scale small images up so tesseract has pixels to work with, but cap the total so a
        # tall screenshot doesn't balloon into a giant bitmap that takes minutes to read
        w, h = img.size
        if w < 1600:
            f = 1600 / w
            w, h = round(w * f), round(h * f)
        if w * h > MAX_PIXELS:
            f = (MAX_PIXELS / (w * h)) ** 0.5
            w, h = round(w * f), round(h * f)
        return img.resize((w, h)) if (w, h) != img.size else img

    @staticmethod
    def _mean(img):
        small = img.resize((48, 48))
        data = small.getdata()
        return sum(data) / len(data)


def load_ocr(tesseract_cmd=None):
    """Builds the tesseract reader. If it isn't installed we return None and the keyword
    method just reads message text instead of image text."""
    try:
        return TesseractOCR(tesseract_cmd)
    except Exception as e:
        log.warning("couldn't load tesseract, image text is off for now (%s)", e)
        return None
