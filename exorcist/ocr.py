import io
import logging

log = logging.getLogger("exorcist.ocr")


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
        return self._pt.image_to_string(img, config="--psm 6")

    def _prep(self, img):
        # clean the image up before tesseract sees it: grayscale, flip dark mode
        # screenshots so the text is dark on light, scale small images up, stretch contrast
        ops = self._ImageOps
        img = img.convert("L")
        if self._mean(img) < 110:
            # most of these scams are dark mode posts, light text on black, which tesseract
            # reads terribly. inverting turns it into dark text on light, which it reads well
            img = ops.invert(img)
        w, h = img.size
        if w < 1600:
            factor = 1600 / w
            img = img.resize((int(w * factor), int(h * factor)))
        return ops.autocontrast(img, cutoff=2)

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
