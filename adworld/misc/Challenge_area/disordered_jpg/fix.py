#!/usr/bin/env python3
# -*- coding: utf-8 -*-

with open("order.jpg", "wb") as fout:
    with open ("disorder.jpg", "rb") as fin:
        data = fin.read(4)
        while data:
            fout.write(data[::-1])
            data = fin.read(4)