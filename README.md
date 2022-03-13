### AES128加密及解密

`flag`对应16进制`0x666c6167`

加密oracle，满足pkcs5padding：

```
enc_oracle 666c6167
```

返回随机128位iv及密文：

```
iv||c = 5df04f5e5dcd655604643a4911cb99a9b3cd8a6b3a56977b5d95eec0906ae886
```

解密oracle，仅验证密文是否满足pkcs5padding：

```
dec_oracle 5df04f5e5dcd655604643a4911cb99a9b3cd8a6b3a56977b5d95eec0906ae886
```

不满足时输出`HTTP 500 server error.`，返回500；满足时输出`HTTP 200.`，返回200.

### Padding Oracle攻击

在已知`iv||c`时，通过解密oracle的返回状态爆破正确的中间值，在不知道key的情况下得到明文。

