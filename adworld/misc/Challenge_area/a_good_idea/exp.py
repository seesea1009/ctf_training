#!/usr/bin/env python3
# -*- coding : utf-8 -*-

import zxing

reader = zxing.BarCodeReader()
print(reader)
barcode = reader.decode("qr.bmp")
barcode = reader.decode("qrcode.png")

print(barcode.parsed)
