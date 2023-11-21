#pragma once

unsigned char hookShellcode[] = {
    0x57, 0x48, 0x89, 0xE7, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x0F, 0x00, 0x00,
    0x00, 0x48, 0x89, 0xFC, 0x5F, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x48, 0xB8, 0x65, 0x00, 0x65, 0x00, 0x70, 0x00, 0x21, 0x00, 0x55, 0x48, 0x89, 0xE5, 0x56, 0x48,
    0xBE, 0x5D, 0x00, 0x20, 0x00, 0x53, 0x00, 0x6C, 0x00, 0x53, 0x48, 0xBB, 0x0D, 0x00, 0x0A, 0x00,
    0x5B, 0x00, 0x2A, 0x00, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x81, 0xEC, 0xF0, 0x00, 0x00, 0x00, 0x48,
    0x89, 0x44, 0x24, 0x50, 0x48, 0x8D, 0x4C, 0x24, 0x40, 0x31, 0xC0, 0x48, 0x89, 0x74, 0x24, 0x48,
    0x48, 0x89, 0x5C, 0x24, 0x40, 0x66, 0x89, 0x44, 0x24, 0x58, 0xE8, 0x01, 0x04, 0x00, 0x00, 0xBA,
    0xFE, 0xE5, 0x19, 0x0E, 0xB9, 0x75, 0xEE, 0x40, 0x70, 0xE8, 0x42, 0x02, 0x00, 0x00, 0xB9, 0x10,
    0x27, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x8D, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x65,
    0x00, 0x65, 0x00, 0x70, 0x00, 0x20, 0x00, 0x48, 0x89, 0xB4, 0x24, 0x98, 0x00, 0x00, 0x00, 0x48,
    0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x53, 0x00, 0x75, 0x00, 0x63, 0x00, 0x63,
    0x00, 0x48, 0xBE, 0x63, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x48, 0x89, 0x84, 0x24, 0xA8,
    0x00, 0x00, 0x00, 0x48, 0xB8, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x48, 0x89, 0x9C,
    0x24, 0x90, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, 0xE8, 0x8E, 0x03,
    0x00, 0x00, 0x8B, 0x15, 0x58, 0x06, 0x00, 0x00, 0x48, 0x8B, 0x0D, 0x41, 0x06, 0x00, 0x00, 0xE8,
    0x7C, 0x06, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x60, 0x48, 0x89, 0x5C, 0x24, 0x60, 0x48, 0xB8,
    0x5D, 0x00, 0x20, 0x00, 0x58, 0x00, 0x6F, 0x00, 0x48, 0x89, 0x44, 0x24, 0x68, 0x48, 0xB8, 0x72,
    0x00, 0x20, 0x00, 0x53, 0x00, 0x75, 0x00, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x89, 0x74, 0x24,
    0x78, 0xC7, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0xE8, 0x3F, 0x03, 0x00,
    0x00, 0xBA, 0xC8, 0x62, 0x29, 0x08, 0xB9, 0xED, 0xB5, 0xD3, 0x22, 0xE8, 0x80, 0x01, 0x00, 0x00,
    0x8B, 0x15, 0xFA, 0x05, 0x00, 0x00, 0x41, 0xB9, 0x20, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC1, 0xFF,
    0xFF, 0xFF, 0xFF, 0x4C, 0x8D, 0x44, 0x24, 0x38, 0x89, 0x54, 0x24, 0x38, 0x48, 0x8D, 0x54, 0x24,
    0x3C, 0x48, 0x89, 0x54, 0x24, 0x20, 0x48, 0x8D, 0x15, 0xC3, 0x05, 0x00, 0x00, 0xFF, 0xD0, 0x48,
    0x8D, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x5D, 0x00, 0x20, 0x00, 0x50, 0x00, 0x72,
    0x00, 0x48, 0x89, 0x9C, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xC8, 0x00, 0x00,
    0x00, 0x48, 0xB8, 0x6F, 0x00, 0x74, 0x00, 0x65, 0x00, 0x63, 0x00, 0x48, 0x89, 0x84, 0x24, 0xD0,
    0x00, 0x00, 0x00, 0x48, 0xB8, 0x74, 0x00, 0x20, 0x00, 0x73, 0x00, 0x75, 0x00, 0x48, 0x89, 0x84,
    0x24, 0xD8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xB4, 0x24, 0xE0, 0x00, 0x00, 0x00, 0xC7, 0x84, 0x24,
    0xE8, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0xE8, 0xA3, 0x02, 0x00, 0x00, 0x49, 0xBA, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2, 0x48, 0x8D, 0x65, 0xF0, 0x5B, 0x5E,
    0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x53, 0xBA, 0xFE, 0xE5, 0x19, 0x0E, 0x89, 0xCB, 0xB9, 0x75, 0xEE, 0x40, 0x70, 0x48, 0x83, 0xEC,
    0x20, 0xE8, 0xAA, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x20, 0x89, 0xD9, 0x5B, 0xFF, 0xE0, 0x90,
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x4C, 0x8B, 0x58,
    0x20, 0x4D, 0x89, 0xDA, 0x4D, 0x8B, 0x42, 0x50, 0x4D, 0x85, 0xC0, 0x74, 0x68, 0x41, 0x0F, 0xB7,
    0x00, 0x66, 0x85, 0xC0, 0x74, 0x6A, 0x4C, 0x89, 0xC2, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x8D, 0x48, 0xBF, 0x66, 0x41, 0x83, 0xF9, 0x19, 0x77, 0x06, 0x83, 0xC0, 0x20, 0x66, 0x89,
    0x02, 0x48, 0x83, 0xC2, 0x02, 0x0F, 0xB7, 0x02, 0x66, 0x85, 0xC0, 0x75, 0xE3, 0x41, 0x0F, 0xB7,
    0x00, 0x66, 0x85, 0xC0, 0x74, 0x3A, 0x41, 0xB9, 0x05, 0x15, 0x00, 0x00, 0x0F, 0x1F, 0x40, 0x00,
    0x44, 0x89, 0xCA, 0x49, 0x83, 0xC0, 0x02, 0xC1, 0xE2, 0x05, 0x01, 0xD0, 0x41, 0x01, 0xC1, 0x41,
    0x0F, 0xB7, 0x00, 0x66, 0x85, 0xC0, 0x75, 0xE8, 0x44, 0x39, 0xC9, 0x74, 0x1E, 0x4D, 0x8B, 0x12,
    0x4D, 0x39, 0xD3, 0x75, 0x8F, 0x31, 0xC0, 0xC3, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0xB9, 0x05, 0x15, 0x00, 0x00, 0x44, 0x39, 0xC9, 0x75, 0xE2, 0x49, 0x8B, 0x42, 0x20, 0xC3,
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x54, 0x57, 0x56, 0x89, 0xCE, 0x53, 0x89, 0xD3, 0x48, 0x83, 0xE4,
    0xF0, 0x48, 0x83, 0xEC, 0x50, 0xE8, 0x46, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x75, 0x71, 0xB9,
    0x75, 0xEE, 0x40, 0x70, 0xE8, 0x37, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x75, 0x12, 0xBA, 0x01,
    0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x59, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,
    0xBA, 0x89, 0x5F, 0xB7, 0x29, 0xB9, 0xED, 0xB5, 0xD3, 0x22, 0xE8, 0xB1, 0xFF, 0xFF, 0xFF, 0xBA,
    0x23, 0xDB, 0x07, 0x03, 0xB9, 0xED, 0xB5, 0xD3, 0x22, 0x49, 0x89, 0xC4, 0xE8, 0x9F, 0xFF, 0xFF,
    0xFF, 0x81, 0xFE, 0xF3, 0xD3, 0x6B, 0x5A, 0x48, 0x89, 0xC7, 0x0F, 0x84, 0xE0, 0x00, 0x00, 0x00,
    0x81, 0xFE, 0x27, 0x94, 0x0D, 0xA7, 0x0F, 0x84, 0x17, 0x01, 0x00, 0x00, 0x89, 0xF1, 0xE8, 0xDD,
    0xFE, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x84, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x40, 0x00,
    0x48, 0x89, 0xC2, 0x48, 0x63, 0x52, 0x3C, 0x44, 0x8B, 0x8C, 0x10, 0x88, 0x00, 0x00, 0x00, 0x49,
    0x01, 0xC1, 0x45, 0x8B, 0x41, 0x20, 0x41, 0x8B, 0x51, 0x18, 0x49, 0x01, 0xC0, 0x85, 0xD2, 0x74,
    0x5F, 0x8D, 0x7A, 0xFF, 0x45, 0x31, 0xD2, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x8B, 0x10, 0xB9, 0x05, 0x15, 0x00, 0x00, 0x48, 0x01, 0xC2, 0x4C, 0x8D, 0x5A, 0x01, 0x0F,
    0xB6, 0x12, 0x84, 0xD2, 0x74, 0x20, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x89, 0xCE, 0x49, 0x83, 0xC3, 0x01, 0xC1, 0xE6, 0x05, 0x01, 0xF2, 0x01, 0xD1, 0x41, 0x0F, 0xB6,
    0x53, 0xFF, 0x84, 0xD2, 0x75, 0xEA, 0x39, 0xCB, 0x74, 0x26, 0x49, 0x8D, 0x52, 0x01, 0x49, 0x83,
    0xC0, 0x04, 0x4C, 0x39, 0xD7, 0x74, 0x09, 0x49, 0x89, 0xD2, 0xEB, 0xB4, 0x0F, 0x1F, 0x40, 0x00,
    0x48, 0x8D, 0x65, 0xE0, 0x31, 0xC0, 0x5B, 0x5E, 0x5F, 0x41, 0x5C, 0x5D, 0xC3, 0x0F, 0x1F, 0x00,
    0x41, 0x8B, 0x49, 0x24, 0x4E, 0x8D, 0x04, 0x50, 0x41, 0x8B, 0x51, 0x1C, 0x41, 0x0F, 0xB7, 0x0C,
    0x08, 0x48, 0x8D, 0x0C, 0x88, 0x8B, 0x14, 0x11, 0x48, 0x8D, 0x65, 0xE0, 0x5B, 0x5E, 0x5F, 0x48,
    0x01, 0xD0, 0x41, 0x5C, 0x5D, 0xC3, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xB8, 0x55, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0xC6, 0x44, 0x24, 0x3E, 0x00, 0x48,
    0x89, 0x44, 0x24, 0x34, 0xB8, 0x6C, 0x6C, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x3C, 0x48, 0x8D,
    0x74, 0x24, 0x40, 0x48, 0x8D, 0x54, 0x24, 0x34, 0x48, 0x89, 0xF1, 0x41, 0xFF, 0xD4, 0x4C, 0x8D,
    0x4C, 0x24, 0x28, 0x49, 0x89, 0xF0, 0x31, 0xD2, 0x31, 0xC9, 0xFF, 0xD7, 0x48, 0x98, 0xE9, 0xF0,
    0xFE, 0xFF, 0xFF, 0x48, 0xB8, 0x53, 0x68, 0x6C, 0x77, 0x61, 0x70, 0x69, 0x2E, 0xC7, 0x44, 0x24,
    0x3C, 0x64, 0x6C, 0x6C, 0x00, 0x48, 0x89, 0x44, 0x24, 0x34, 0xEB, 0xC2, 0x90, 0x90, 0x90, 0x90,
    0x55, 0xBA, 0xDB, 0xEC, 0xA5, 0x15, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41,
    0x54, 0x57, 0x56, 0x53, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x81, 0xEC, 0x10, 0x01, 0x00, 0x00, 0x48,
    0x89, 0x4D, 0x10, 0xB9, 0xED, 0xB5, 0xD3, 0x22, 0xE8, 0x23, 0xFE, 0xFF, 0xFF, 0xBA, 0xB2, 0x26,
    0x93, 0xD6, 0xB9, 0xED, 0xB5, 0xD3, 0x22, 0x48, 0x8D, 0x5C, 0x24, 0x70, 0x48, 0x89, 0xC7, 0xE8,
    0x0C, 0xFE, 0xFF, 0xFF, 0xBA, 0x89, 0x5F, 0xB7, 0x29, 0xB9, 0xED, 0xB5, 0xD3, 0x22, 0x4C, 0x8D,
    0xB4, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC5, 0xE8, 0xF2, 0xFD, 0xFF, 0xFF, 0xBA, 0x3D,
    0x13, 0x8E, 0x8B, 0xB9, 0xED, 0xB5, 0xD3, 0x22, 0x4C, 0x8D, 0x7C, 0x24, 0x68, 0x48, 0x89, 0xC6,
    0xE8, 0xDB, 0xFD, 0xFF, 0xFF, 0x48, 0x8D, 0x94, 0x24, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD9,
    0x49, 0x89, 0xC4, 0x48, 0xB8, 0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x5C, 0x00, 0x48, 0x89, 0x84,
    0x24, 0xD0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x77, 0x00, 0x48,
    0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F,
    0x00, 0x48, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x77, 0x00, 0x73, 0x00, 0x5C,
    0x00, 0x74, 0x00, 0x48, 0x89, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x65, 0x00, 0x6D,
    0x00, 0x70, 0x00, 0x5C, 0x00, 0x48, 0x89, 0x84, 0x24, 0xF0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x6C,
    0x00, 0x6F, 0x00, 0x67, 0x00, 0x2E, 0x00, 0x48, 0x89, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00, 0x48,
    0xB8, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x00, 0x01, 0x00,
    0x00, 0xFF, 0xD6, 0x48, 0x89, 0x9C, 0x24, 0xB0, 0x00, 0x00, 0x00, 0x4D, 0x89, 0xF0, 0x4C, 0x89,
    0xF9, 0x48, 0x8D, 0x9C, 0x24, 0x80, 0x00, 0x00, 0x00, 0xBA, 0xFF, 0x01, 0x1F, 0x00, 0xC7, 0x84,
    0x24, 0xA0, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x84, 0x24, 0xA8, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x89, 0xD9, 0xC7, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00, 0x40,
    0x00, 0x00, 0x00, 0x48, 0xC7, 0x84, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
    0xC7, 0x84, 0x24, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x50, 0x00,
    0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x48, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x40,
    0x20, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x38, 0x02, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x30,
    0x03, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24,
    0x20, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD7, 0x85, 0xC0, 0x74, 0x4A, 0xC7, 0x44, 0x24, 0x50, 0x00,
    0x00, 0x00, 0x00, 0x49, 0x89, 0xD9, 0x4D, 0x89, 0xF0, 0xBA, 0x04, 0x00, 0x10, 0x00, 0x48, 0xC7,
    0x44, 0x24, 0x48, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x89, 0xF9, 0xC7, 0x44, 0x24, 0x40, 0x20, 0x00,
    0x00, 0x00, 0xC7, 0x44, 0x24, 0x38, 0x03, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x30, 0x02, 0x00,
    0x00, 0x00, 0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xD7, 0x48, 0x8D, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x55,
    0x10, 0xFF, 0xD6, 0x0F, 0xB7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9, 0x45, 0x31,
    0xC0, 0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0x4C, 0x24, 0x68, 0x31, 0xD2, 0x48, 0xC7, 0x44,
    0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00, 0x89,
    0x44, 0x24, 0x30, 0x48, 0x8B, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x28,
    0x41, 0xFF, 0xD5, 0x48, 0x8B, 0x4C, 0x24, 0x68, 0x41, 0xFF, 0xD4, 0x48, 0x8D, 0x65, 0xC8, 0x5B,
    0x5E, 0x5F, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90,
    0x01, 0x02, 0x03, 0x04, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x4D, 0x85, 0xC0, 0x74, 0x1D, 0x31, 0xC0, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x0F, 0xB6, 0x0C, 0x02, 0x44, 0x88, 0x0C, 0x01, 0x48, 0x83, 0xC0, 0x01, 0x49, 0x39, 0xC0,
    0x75, 0xEE, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x80, 0x39, 0x00, 0x74, 0x1B, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,
    0x89, 0xD0, 0x48, 0x83, 0xC2, 0x01, 0x80, 0x7C, 0x11, 0xFF, 0x00, 0x75, 0xF3, 0xC3, 0x66, 0x90,
    0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xDE, 0xAD, 0x10, 0xAF, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2, 0xC3, 0x90, 0x90,
    0x89, 0xD2, 0x44, 0x8B, 0x05, 0x47, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0xC8, 0x49, 0x89, 0xD2, 0x49,
    0xC1, 0xEA, 0x02, 0x4E, 0x8D, 0x0C, 0x91, 0x4D, 0x85, 0xD2, 0x74, 0x10, 0x0F, 0x1F, 0x40, 0x00,
    0x44, 0x31, 0x00, 0x48, 0x83, 0xC0, 0x04, 0x4C, 0x39, 0xC8, 0x75, 0xF4, 0x49, 0xC1, 0xE2, 0x02,
    0x4A, 0x8D, 0x04, 0x11, 0x48, 0x01, 0xD1, 0x4C, 0x39, 0xD2, 0x76, 0x14, 0x0F, 0x1F, 0x40, 0x00,
    0x44, 0x30, 0x00, 0x48, 0x83, 0xC0, 0x01, 0x48, 0x39, 0xC1, 0x75, 0xF4, 0xC3, 0x0F, 0x1F, 0x00,
    0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};