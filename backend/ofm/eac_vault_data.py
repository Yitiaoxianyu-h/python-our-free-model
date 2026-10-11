"""EAC 车道密封材料（生成物，勿手改）。

与上游 ``src/vault-data.js`` / ``src/vault-anchor.js`` 逐字一致：两片掩码分片 +
锚片分片 + 打包的 AES-256-GCM 载荷。**明文不存在于本仓库**，与上游同一设计。

解锁算法见 ``ofm/eac_vault.py``。
"""

#: 两片掩码分片（``s`` = 掩码后的字节，``w`` = 该片的种子）。
LANE_SHARDS = [
    {"s": "ZNOAoI0gQDLQJ7iI9T8BCiD7HI1WDeep", "w": "7SwffsKLymPWeg9LskEIfw=="},
    {"s": "GdDFDPMbIpZAB0PxlqjLiqyal/znPi5C", "w": "1uMy322DuCNectE+zVAAcw=="},
]

#: 锚片分片（与上面两片同构，位于另一个文件）。
LANE_ANCHOR = {"s": "ivi0Yd+KNFs671wb1QsMmU16uRo26005", "w": "SXLUjrr2xEdsPY2v+2Ef3Q=="}

#: 打包的载荷：``iv(12) | ciphertext | tag(16)``，base64。
LANE_SEAL = (
    "K6ir4hSvjDLKLQBlGC8GBGiPKOlbqabhYDHNG+GZQQG6iUoRuLXH7F7fRAzvULNIPT8Kzpn3aQwTcNt4SsoP"
    "qxqb5bFujLRo0YM5CYZx/VymLHTh9s9t5d8DnN8Tp4kBkNEA0HCv5MgiS9xfiQm77FrQKKarCpxNRAKnRt"
    "hyz4McS5UhxcEJ+SqlJB4UcE5ljXaXbqix"
)
