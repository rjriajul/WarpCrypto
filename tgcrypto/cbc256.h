/*
 * WarpCrypto - Fast and Portable Cryptography Extension Library
 * Originally based on TgCrypto (Pyrogram) by Dan <https://github.com/delivrance>
 * Copyright (C) 2017-present Dan <https://github.com/delivrance>
 *
 * This file is part of WarpCrypto.
 *
 * WarpCrypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * WarpCrypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with WarpCrypto.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CBC256_H
#define CBC256_H

uint8_t *cbc256(const uint8_t in[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t encrypt);

#endif  // CBC256_H
